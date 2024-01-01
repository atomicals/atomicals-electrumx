# -*- coding: utf-8 -*-

import json
import traceback


from aiohttp import web, web_middlewares


def error_resp(status_code: int, exception: Exception) -> web.Response:
    return web.Response(
        status=status_code,
        body=json.dumps({
            "success": False,
            'code': 1,
            'message': str(exception)
        }).encode('utf-8'),
        content_type='application/json')

def success_resp(data) -> web.Response:
    result = {"success": True,"response": data}
    return web.json_response(data=result)

def request_middleware(self) -> web_middlewares:
    async def factory(app: web.Application, handler):
        async def middleware_handler(request):
            print('Request {} comming'.format(request))
            # self.logger.info('Request {} comming'.format(request))
            response = await handler(request)
            if isinstance(response, web.Response):
                return response
            return success_resp(response)
        return middleware_handler
    return factory


def error_middleware(self) -> web_middlewares:
    async def factory(app: web.Application, handler):
        async def middleware_handler(request):
            try:
                response = await handler(request)
                if response.status == 404 or response.status == 400:
                    return error_resp(response.status, Exception(response.text))
                return response
            except web.HTTPException as ex:
                if ex.status == 404:
                    return error_resp(ex.status, ex)
                raise
            except Exception as e:
                self.logger.warning('Request {} has failed with exception: {}'.format(request, repr(e)))
                self.logger.warning(traceback.format_exc())
                return error_resp(500, e)
        return middleware_handler
    return factory