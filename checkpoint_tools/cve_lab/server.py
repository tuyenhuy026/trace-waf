"""Standalone, deliberately misconfigured aiohttp STATIC server for authorized lab ONLY.

No real files or secrets are exposed; only a synthetic marker is accessible.
Versions are selected via Docker build args, not fetched from arbitrary URLs.
"""
from aiohttp import web
import aiohttp
from pathlib import Path

BASE=Path('/lab')

@web.middleware
async def marker(request,handler):
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        response = exc
    response.headers['X-Trace-Request'] = request.headers.get('X-Trace-Request','')
    return response

async def meta(request):
    return web.json_response({'product':'aiohttp','version':aiohttp.__version__,
       'configuration':'static-follow_symlinks-true',
       'static_root':str(BASE/'static'),
       'filesystem_probe':'synthetic-marker-only',
       'lab':'TRACE-WAF CVE-2024-23334'})

app=web.Application(middlewares=[marker])
app.router.add_get('/meta',meta)
# The intended vulnerable configuration for reproducing CVE-2024-23334.
app.router.add_static('/static',str(BASE/'static'),follow_symlinks=True)
web.run_app(app,host='0.0.0.0',port=8080)
