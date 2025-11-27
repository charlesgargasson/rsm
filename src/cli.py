#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio, sys, signal
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--rsm-ip', type=str, default="127.0.0.1")
parser.add_argument('--rsm-port', type=int, default=7866)
args = parser.parse_args()

sys.stdin.reconfigure(encoding='utf-8')

async def ainput() -> str:
    loop = asyncio.get_event_loop()
    data = await loop.run_in_executor(None, sys.stdin.readline)
    return data.encode('utf-8')

async def handle_reader(reader: asyncio.StreamReader) -> None:
    data = b""
    while (not reader.at_eof()):
        data += await reader.read(1)
        try :
            data = data.decode('utf-8')
            sys.stdout.write(data)
            sys.stdout.flush() 
            data = b""
            continue
        except :
            pass
        
        if (len(data) == 4) or (b"\n" in data) or (b"\r" in data):
            data = data.decode('utf-8','ignore')
            sys.stdout.write(data)
            sys.stdout.flush() 
            data = b""

async def handle_writer(writer: asyncio.StreamWriter) -> None:
    if len(sys.argv) > 1:
        session = sys.argv[1] + "\n"
    else:
        session = "\n"
    writer.write(f"{session}".encode('utf-8'))
    await writer.drain()

    try:
        while (not writer.is_closing()):
            userinput = await ainput()
            writer.write(userinput)
            await writer.drain()
    except KeyboardInterrupt:
        print("[*] Exiting RSM CLI ..")
        writer.close()
        await writer.wait_closed()
        print("[*] CLI writer closed, the reverseshell session still running")
        return

async def rsm_client(HOST: str, PORT: int) -> None:
    reader, writer = await asyncio.open_connection(HOST, PORT)
    tasks = []

    task = asyncio.create_task(handle_reader(reader))
    tasks.append(task)

    task = asyncio.create_task(handle_writer(writer))
    tasks.append(task)

    await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)

    writer.close()
    await writer.wait_closed()

async def asyncmain() -> None:
    tasks = []

    task = asyncio.create_task(rsm_client(args.rsm_ip, args.rsm_port))
    tasks.append(task)

    await asyncio.gather(*tasks)

def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    #loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncmain())

if __name__ == '__main__':
    main()
