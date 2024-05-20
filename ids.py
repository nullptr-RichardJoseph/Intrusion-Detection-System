# Main IDS application 
import argparse
from network.monitoring import start_sniffing

def main():
    parser=argparse.ArgumentParser(description= "Intrustion Detection System")
    parser.add_argument('-i', '--interface', type=str, required=True, help ="Network interface to capture packets from")
    args=parser.parse_args()

    start_sniffing(args.interface)

if __name__=="__main__":
        main()