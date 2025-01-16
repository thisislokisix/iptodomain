import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def resolve_ip(ip):
    try:
        # Perform reverse DNS lookup
        domain = socket.gethostbyaddr(ip.strip())[0]
        return ip.strip(), domain
    except (socket.herror, socket.error):
        # Handle invalid IPs or resolution errors
        return ip.strip(), None

def process_ips(ips, result_file):
    unique_domains = set()  # Store unique domains
    total_ips = len(ips)
    resolved_count = 0

    with ThreadPoolExecutor(max_workers=50) as executor:  # Use multithreading for speed
        
        future_to_ip = {executor.submit(resolve_ip, ip): ip for ip in ips}

        for future in as_completed(future_to_ip):
            ip, domain = future.result()
            resolved_count += 1

            if domain:
                print(f"[{resolved_count}/{total_ips}] {ip} >> {Fore.GREEN}{domain}{Style.RESET_ALL}")
                unique_domains.add(domain)
                # Update result.txt in real-time
                with open(result_file, "a") as file:
                    file.write(domain + "\n")
            else:
                print(f"[{resolved_count}/{total_ips}] {ip} >> {Fore.RED}Failed to resolve{Style.RESET_ALL}")

    return unique_domains

def main():
  
    input_file = input("Enter the IP list file (e.g., list.txt): ").strip()
    result_file = "result.txt"

    open(result_file, "w").close()

    try:
        with open(input_file, "r") as file:
            ips = file.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File '{input_file}' not found!{Style.RESET_ALL}")
        return

    unique_domains = process_ips(ips, result_file)

    print(f"\n{Fore.GREEN}Resolved {len(unique_domains)} unique domains. Results saved to {result_file}.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
