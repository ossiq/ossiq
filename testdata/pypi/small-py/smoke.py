# pydantic 2 moved BaseSettings to pydantic-settings: an upgrade past 1.x must fail here.
# Named smoke.py, not test_*.py, so the repo's own `pytest .` does not collect it.
from pydantic import BaseSettings


class Settings(BaseSettings):
    name: str = "small-py"


assert Settings().name == "small-py"
print("ok")
