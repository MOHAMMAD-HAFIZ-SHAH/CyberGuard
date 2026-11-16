
import asyncio
import json
import os
import uuid
from typing import Any

import httpx

try:
    from mcp import Client
except ImportError:
    Client = None

try:
    from a2a.client import A2ACardResolver, create_client
    from a2a.helpers import get_artifact_text, get_message_text
except ImportError:
    A2ACardResolver = None
    create_client = None
    get_artifact_text = None
    get_message_text = None


MCP_SERVER_URL = os.getenv(
    "CYBERGUARD_MCP_URL",
    "http://127.0.0.1:8100/mcp",
)

A2A_SERVER_URL = os.getenv(
    "CYBERGUARD_A2A_URL",
    "http://127.0.0.1:8000/",
)


def _make_json_safe(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")

    if isinstance(value, dict):
        return {
            str(key): _make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_make_json_safe(item) for item in value]

    return value


async def _call_mcp_tool(
    tool_name: str,
    arguments: dict[str, Any],
) -> Any:
    async with Client(MCP_SERVER_URL) as client:
        result = await client.call_tool(tool_name, arguments)

        if getattr(result, "is_error", False):
            raise RuntimeError(
                f"MCP tool '{tool_name}' returned an error."
            )

        structured = getattr(result, "structured_content", None)

        if structured is not None:
            return structured

        text_parts = [
            item.text
            for item in getattr(result, "content", [])
            if hasattr(item, "text")
        ]

        if text_parts:
            combined = "\n".join(text_parts)

            try:
                return json.loads(combined)
            except json.JSONDecodeError:
                return {"text": combined}

        return {}


def call_mcp_tool(
    tool_name: str,
    arguments: dict[str, Any],
) -> Any:
    return asyncio.run(
        _call_mcp_tool(tool_name, arguments)
    )


async def _call_a2a_review(
    payload: dict[str, Any],
) -> dict[str, Any]:
    safe_payload = _make_json_safe(payload)
    request_text = json.dumps(
        safe_payload,
        ensure_ascii=False,
    )

    async with httpx.AsyncClient(timeout=120.0) as httpx_client:
        resolver = A2ACardResolver(
            httpx_client,
            A2A_SERVER_URL,
        )

        agent_card = await resolver.get_agent_card()
        client = await create_client(agent_card)

        try:
            message = Message(
                role=Role.ROLE_USER,
                message_id=str(uuid.uuid4()),
                context_id=str(uuid.uuid4()),
                parts=[Part(text=request_text)],
            )

            request = SendMessageRequest(message=message)
            stream = client.send_message(request)

            response_text = None

            async for event in stream:
                if event.HasField("artifact_update"):
                    response_text = get_artifact_text(
                        event.artifact_update.artifact,
                        delimiter=" ",
                    )

                elif event.HasField("message"):
                    response_text = get_message_text(
                        event.message,
                        delimiter=" ",
                    )

            if not response_text:
                raise RuntimeError(
                    "A2A agent did not return a review result."
                )

            try:
                parsed = json.loads(response_text)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    "A2A agent returned invalid JSON."
                ) from error

            if not isinstance(parsed, dict):
                raise RuntimeError(
                    "A2A review result must be a JSON object."
                )

            return parsed

        finally:
            await client.close()


def call_a2a_review(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return asyncio.run(
        _call_a2a_review(payload)
    )
