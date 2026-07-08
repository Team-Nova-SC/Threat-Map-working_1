import httpx, asyncio
async def test():
    async with httpx.AsyncClient(timeout=15.0) as client:
        for ind, typ in [('google.com','domain'), ('8.8.8.8','ip'), ('mccmulund.ac.in','domain'), ('http://malware.wicar.org/data/eicar.com','url')]:
            res = await client.get(f'http://localhost:8000/api/v1/scan?indicator={ind}&type={typ}')
            data = res.json()
            print(f'{ind}: Score {data.get("risk_score")}, Level {data.get("risk_level")}, Summary: {data.get("summary")}')
asyncio.run(test())
