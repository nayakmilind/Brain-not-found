from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from faker import Faker

PersonaPattern = Literal["contact", "profile", "all"]


@dataclass(frozen=True)
class SyntheticPersona:
    seed: int
    pattern: PersonaPattern
    name: str
    email: str
    content: str


def generate_persona(seed: int, pattern: PersonaPattern = "all") -> SyntheticPersona:
    if seed < 0 or seed > 2_147_483_647:
        raise ValueError("Persona seed must be between 0 and 2147483647")
    faker = Faker("en_US")
    faker.seed_instance(seed)
    name = f"{faker.first_name()} Example"
    email = f"persona-{seed}@example.test"
    lines = [f"Name: {name}", f"Email: {email}"]
    if pattern in {"contact", "all"}:
        lines.append(f"Phone: +1 (202) 555-01{seed % 100:02d}")
    if pattern in {"profile", "all"}:
        lines.append(f"Public profile handle: @demo_persona_{seed}")
    return SyntheticPersona(
        seed=seed,
        pattern=pattern,
        name=name,
        email=email,
        content="\n".join(lines),
    )
