from __future__ import annotations

import argparse
import json

from app.modules.demo.persona import generate_persona


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic Privacy Shield demo persona")
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument(
        "--pattern",
        choices=("contact", "profile", "all"),
        default="all",
    )
    arguments = parser.parse_args()
    persona = generate_persona(arguments.seed, arguments.pattern)
    print(
        json.dumps(
            {
                "synthetic": True,
                "seed": persona.seed,
                "pattern": persona.pattern,
                "content": persona.content,
            },
            ensure_ascii=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
