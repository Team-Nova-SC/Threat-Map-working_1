import httpx
import asyncio

async def test():
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post('http://127.0.0.1:8000/api/v1/spiderfoot/scan', json={'target': '8.8.4.4'})
            print("Status:", r.status_code)
            print("JSON:", r.json())
    except Exception as e:
        print("Error:", type(e), e)

if __name__ == "__main__":
    asyncio.run(test())
