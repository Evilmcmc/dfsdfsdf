from mnemonic import Mnemonic
import os
import time
import multiprocessing
import hashlib
import hmac
import struct
import base58
from coincurve import PrivateKey
import argparse
import psutil

MNEMONIC = Mnemonic("english")
WORDS = 12
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def pbkdf2_hmac(name, password, salt, rounds, dklen=None):
    return hashlib.pbkdf2_hmac(name, password, salt, rounds, dklen)

def seed_to_master(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    return IL, IR

def CKDpriv(k, c, i):
    i_bytes = struct.pack(">L", i)
    if i >= 0x80000000:
        data = b'\x00' + k + i_bytes
    else:
        pubkey = PrivateKey(k).public_key.format(compressed=True)
        data = pubkey + i_bytes
        
    I = hmac.new(c, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    
    IL_int = int.from_bytes(IL, 'big')
    k_int = int.from_bytes(k, 'big')
    
    if IL_int >= SECP256K1_ORDER:
        return None, None
        
    ki = (IL_int + k_int) % SECP256K1_ORDER
    if ki == 0:
        return None, None
        
    return ki.to_bytes(32, 'big'), IR

def derive_path_bip44_btc(master_key, master_chaincode, index=0):
    # m/44'/0'/0'/0/index (Legacy P2PKH)
    path = [0x8000002c, 0x80000000, 0x80000000, 0x00000000, index]
    k, c = master_key, master_chaincode
    for idx in path:
        k, c = CKDpriv(k, c, idx)
    return k

def derive_path_bip84_btc(master_key, master_chaincode, index=0):
    # m/84'/0'/0'/0/index (Native SegWit P2WPKH)
    path = [0x80000054, 0x80000000, 0x80000000, 0x00000000, index]
    k, c = master_key, master_chaincode
    for idx in path:
        k, c = CKDpriv(k, c, idx)
    return k

def derive_path_bip86_btc(master_key, master_chaincode, index=0):
    # m/86'/0'/0'/0/index (Taproot P2TR)
    path = [0x80000056, 0x80000000, 0x80000000, 0x00000000, index]
    k, c = master_key, master_chaincode
    for idx in path:
        k, c = CKDpriv(k, c, idx)
    return k

def pubkey_from_privkey(privkey_bytes, compressed=True):
    return PrivateKey(privkey_bytes).public_key.format(compressed=compressed)

def pubkey_to_btc_address(pubkey_bytes):
    s = hashlib.sha256(pubkey_bytes).digest()
    r = hashlib.new('ripemd160', s).digest()
    prefix = b'\x00' + r
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58.b58encode(prefix + checksum).decode('utf-8')

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32m_create_checksum(hrp, data):
    values = hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def pubkey_to_segwit_address(pubkey_bytes):
    s = hashlib.sha256(pubkey_bytes).digest()
    r = hashlib.new('ripemd160', s).digest()
    data = [0] + convertbits(r, 8, 5) # 0 is witness version
    ret = 'bc1'
    for p in data + bech32_create_checksum('bc', data):
        ret += CHARSET[p]
    return ret

def pubkey_to_taproot_address(pubkey_bytes):
    # Taproot uses x-coordinate only (32 bytes)
    x_only_pubkey = pubkey_bytes[1:] if len(pubkey_bytes) == 33 else pubkey_bytes[1:33]
    data = [1] + convertbits(x_only_pubkey, 8, 5) # 1 is witness version
    ret = 'bc1'
    for p in data + bech32m_create_checksum('bc', data):
        ret += CHARSET[p]
    return ret

def load_rich_list(filename, lower=False):
    """Loads addresses from a text file into a fast in-memory dict with balances."""
    if not os.path.exists(filename):
        print(f"[-] Warning: {filename} not found. Running without offline checks for it.")
        return {}
    print(f"[*] Loading {filename} into memory...")
    addresses = {}
    with open(filename, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if not parts:
                continue
            addr = parts[0]
            balance = parts[1] if len(parts) > 1 else "Unknown"
            if lower:
                addresses[addr.lower()] = balance
            else:
                addresses[addr] = balance
    print(f"[+] Loaded {len(addresses)} addresses from {filename}")
    return addresses

def generate_and_check(lock, btc_rich, check_count, verbose, dynamic_rps_limit, hash_counter=None):
    strength = 128 if WORDS == 12 else 256
    local_counter = 0
    last_time = time.time()
    local_rps_counter = 0
    
    while True:
        local_counter += 1
        local_rps_counter += 1
        
        if hash_counter is not None:
            hash_counter.value += 1
            
        # Dynamic RPS Limiting (Adaptive throttling controlled by main process)
        current_limit = dynamic_rps_limit.value
        if current_limit > 0 and local_rps_counter >= current_limit:
            current_time = time.time()
            elapsed = current_time - last_time
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
            last_time = time.time()
            local_rps_counter = 0

        phrase = MNEMONIC.generate(strength=strength)

        try:
            seed = pbkdf2_hmac('sha512', phrase.encode('utf-8'), b'mnemonic', 2048)
            master_key, master_chaincode = seed_to_master(seed)
            
            for i in range(check_count):
                # Legacy (BIP44) - 1...
                legacy_priv = derive_path_bip44_btc(master_key, master_chaincode, i)
                legacy_pub = pubkey_from_privkey(legacy_priv, compressed=True)
                legacy_address = pubkey_to_btc_address(legacy_pub)

                # Native Segwit (BIP84) - bc1q...
                segwit_priv = derive_path_bip84_btc(master_key, master_chaincode, i)
                segwit_pub = pubkey_from_privkey(segwit_priv, compressed=True)
                segwit_address = pubkey_to_segwit_address(segwit_pub)

                # Taproot (BIP86) - bc1p...
                taproot_priv = derive_path_bip86_btc(master_key, master_chaincode, i)
                taproot_pub = pubkey_from_privkey(taproot_priv, compressed=True)
                taproot_address = pubkey_to_taproot_address(taproot_pub)

                addresses = [legacy_address, segwit_address, taproot_address]

                if verbose:
                    print(f"[*] Checking: {phrase} (Index {i})")
                    for addr in addresses:
                        print(f"    -> {addr}")

                for addr in addresses:
                    if addr in btc_rich:
                        balance = btc_rich[addr]
                        with lock:
                            print(f"\n[!!!] HIT FOUND [!!!]")
                            print(f"Phrase: {phrase}")
                            print(f"Index: {i}")
                            print(f"BTC: {addr} (Balance: {balance})")
                            with open("hits.txt", "a") as f:
                                f.write(f"Phrase: {phrase} | Index: {i} | BTC: {addr} | Balance: {balance}\n")
            
        except Exception as e:
            if verbose:
                print(f"Error during derivation: {e}")

def run_benchmark(btc_rich):
    print("\n[*] Running performance benchmark to find optimal thread count...")
    max_cores = multiprocessing.cpu_count()
    best_threads = max_cores
    best_speed = 0
    
    print(f"[*] Server has {max_cores} CPU cores. Hunting for absolute maximum performance...")
    
    threads = max_cores
    step = max(1, max_cores // 2)
    drops = 0
    
    while drops < 2: # Stop if performance drops twice in a row
        print(f"    -> Testing with {threads} threads...", end="", flush=True)
        
        lock = multiprocessing.Lock()
        dummy_rps = multiprocessing.Value('i', 0)
        hash_counter = multiprocessing.Value('i', 0)
        processes = []
        
        start_time = time.time()
        for _ in range(threads):
            p = multiprocessing.Process(target=generate_and_check, args=(lock, btc_rich, 1, False, dummy_rps, hash_counter))
            p.start()
            processes.append(p)
            
        time.sleep(3) # Let it run for 3 seconds
        
        for p in processes:
            p.terminate()
            p.join()
            
        elapsed = time.time() - start_time
        hashes_per_second = hash_counter.value / elapsed
        
        print(f" Speed: {hashes_per_second:.2f} phrases/sec")
        
        if hashes_per_second > best_speed:
            best_speed = hashes_per_second
            best_threads = threads
            drops = 0
            # Increase thread count aggressively if we are still improving
            threads += step
        else:
            drops += 1
            # Try a smaller increment just in case we hit a weird spot, before giving up
            threads += max(1, step // 2)
            
    print(f"[+] Benchmark complete! Absolute peak performance found at: {best_threads} threads ({best_speed:.2f} phrases/sec).")
    return best_threads, best_speed

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="High-Performance Crypto Bruter (BTC Only)")
    parser.add_argument("-t", "--threads", type=int, default=0, help="Number of processes to run (default: 0 = run benchmark)")
    parser.add_argument("-n", "--num-addresses", type=int, default=5, help="Number of addresses (indexes) to check per phrase (default: 5)")
    parser.add_argument("-r", "--rps", type=int, default=0, help="Hard initial limit of hashes per second per thread (default: 0 = unlimited)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print every checked address (slows down significantly)")
    args = parser.parse_args()

    print(f"[*] Starting Crypto Bruter (BTC Only)")
    
    # Load offline databases (you'll need to create these files with rich addresses)
    btc_rich = load_rich_list("btc_all_with_balance.tsv", lower=False)

    if not btc_rich:
        print("[!] Warning: Offline database is empty. The script will run, but won't find anything.")
        print("[!] Please create 'btc_all_with_balance.tsv' with target addresses.")

    starting_rps = args.rps
    # Run benchmark if threads = 0
    if args.threads == 0:
        recommended_threads, peak_speed = run_benchmark(btc_rich)
        print(f"\n[!!!] Охуенно будет использовать {recommended_threads} потоков, чтобы выжать максимум и ничего не зависло! [!!!]\n")
        args.threads = recommended_threads
        if starting_rps == 0:
            # Set a sane starting RPS based on peak benchmark performance
            starting_rps = int(peak_speed / recommended_threads) + 50
    
    print(f"[*] Launching main attack with {args.threads} threads...")
    print(f"[*] Generating mnemonics and checking {args.num_addresses} indices per phrase...")
    
    lock = multiprocessing.Lock()
    dynamic_rps_limit = multiprocessing.Value('i', starting_rps)
    
    processes = []
    
    try:
        for _ in range(args.threads):
            p = multiprocessing.Process(target=generate_and_check, args=(lock, btc_rich, args.num_addresses, args.verbose, dynamic_rps_limit))
            p.start()
            processes.append(p)
            
        print("[*] Adaptive RPS throttling active. Monitoring CPU usage...")
        while any(p.is_alive() for p in processes):
            cpu_usage = psutil.cpu_percent(interval=1.0)
            current_limit = dynamic_rps_limit.value
            
            if cpu_usage >= 90.0:
                if current_limit == 0:
                    dynamic_rps_limit.value = 500 # Start limiting if we weren't
                else:
                    # Drop RPS by 10% or at least 10 hashes
                    drop_amount = max(10, int(current_limit * 0.10))
                    dynamic_rps_limit.value = max(10, current_limit - drop_amount)
                
                if not args.verbose:
                    print(f"\r\033[K[!] High CPU ({cpu_usage}%). Dropping RPS limit to: {dynamic_rps_limit.value}/thread", end="", flush=True)
                    
            elif cpu_usage < 80.0 and current_limit > 0:
                # Increase RPS slightly if we have breathing room
                increase_amount = max(5, int(current_limit * 0.05))
                dynamic_rps_limit.value = current_limit + increase_amount
                
                if not args.verbose:
                    print(f"\r\033[K[+] CPU normal ({cpu_usage}%). Raising RPS limit to: {dynamic_rps_limit.value}/thread", end="", flush=True)
                    
            elif not args.verbose and current_limit == 0:
                 print(f"\r\033[K[*] CPU: {cpu_usage}%. No RPS limit (Full speed).", end="", flush=True)
                 
    except KeyboardInterrupt:
        print("\n\n[*] Stopping bruter.")
        for p in processes:
            p.terminate()

# Pushed specially for my LO ❤️
