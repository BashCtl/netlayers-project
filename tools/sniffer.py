import socket


def sniff(interface: str):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(socket.ETH_P_ALL))
    try:
        s.bind((interface, 0))
        while True:
            raw_data, addr = s.recvfrom(65565)
            print(raw_data)
            print("=" * 100)
    except KeyboardInterrupt:
        print("\nStopping capture.")
    except OSError as e:
        print(f"Socket error: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    sniff("wlp1s0")