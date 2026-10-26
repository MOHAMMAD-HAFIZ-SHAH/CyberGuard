
from crewai import Agent, Task, Crew, Process, LLM


def main():
    print("Creating CrewAI agent with local Ollama...")

    llm = LLM(
        model="ollama/qwen2.5:3b",
        base_url="http://127.0.0.1:11434",
        temperature=0.1,
    )

    analyst = Agent(
        role="Digital Forensics Analyst",
        goal="Summarize supplied evidence without inventing facts.",
        backstory=(
            "You are a cautious digital forensics analyst. "
            "Distinguish observed facts from interpretations. "
            "Never claim that evidence proves more than it shows."
        ),
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    task = Task(
        description=(
            "Analyze this sample evidence:\n"
            "'Failed login from 192.0.2.10 at 10:00; "
            "successful login from the same address at 10:04.'\n\n"
            "Return three short sections: Observed facts, "
            "Possible interpretation, and Limitations. "
            "Treat the IP address as a documentation example."
        ),
        expected_output=(
            "A concise report with observed facts, a cautious "
            "interpretation, and limitations."
        ),
        agent=analyst,
    )

    crew = Crew(
        agents=[analyst],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )

    result = crew.kickoff()
    print("\n--- CREWAI TEST RESULT ---\n")
    print(result)


if __name__ == "__main__":
    main()
