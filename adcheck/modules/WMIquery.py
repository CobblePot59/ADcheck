from aiowmi.connection import Connection
from aiowmi.query import Query


class WMIquery():
    def __init__(self, remoteHost, username, password, domain, query, namespace):
        self.__remoteHost = remoteHost
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__query = query
        self.__namespace = namespace
        self.__wmiConnection = None

    async def connect(self):
        self.__wmiConnection = Connection(self.__remoteHost, self.__username, self.__password, domain=self.__domain)
        await self.__wmiConnection.connect()

    async def run(self):
        await self.connect()
 
        query = Query(self.__query, self.__namespace)
        service = await self.__wmiConnection.negotiate_ntlm()

        results = []
        async with query.context(self.__wmiConnection, service) as qc:
            async for props in qc.results():
                dict_props = {}
                for name, prop in props.items():
                    dict_props[name] = prop.value
                results.append(dict_props)
        return results