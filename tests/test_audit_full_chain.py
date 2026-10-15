import uuid

import pytest

from app.telemetry.audit import verify_chain


@pytest.mark.asyncio
async def test_verify_chain_has_no_fixed_limit():
    class Result:
        def scalars(self):
            return self

        def all(self):
            return []

    class Session:
        def __init__(self):
            self.statement = None

        async def execute(self, statement):
            self.statement = statement
            return Result()

    session = Session()
    result = await verify_chain(session, uuid.uuid4())

    assert result["valid"] is True
    assert session.statement is not None
    assert session.statement._limit_clause is None
