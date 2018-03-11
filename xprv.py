#!/usr/bin/python3
from electrum import bitcoin
import ecdsa, sys, datetime, argparse

default_derivation_path = datetime.date.today().strftime( "m/%Y'/%m'/%d'" )
key_types = [ 'standard', 'p2wpkh', 'p2wpkh-p2sh', 'p2wsh-p2sh', 'p2pkh', 'p2wsh' ]
entropy_size = 32 #in bytes
    
parser = argparse.ArgumentParser( description="Generate extended keys" )

mkey_group = parser.add_mutually_exclusive_group( required=True )
mkey_group.add_argument( "-g", "--generate-master", help="Generate master private key of type (standard|p2wpkh|p2wpkh-p2sh|p2wsh-p2sh|p2wsh|p2pkh)", choices=key_types, dest="gen_master")
mkey_group.add_argument( "-m", "--master", help="provide master private key \"-\" to read from stdin", dest="master_key" )

output_group = parser.add_argument_group(description="Output options")
output_group.add_argument( "-d", "--derivation-path", help="derivation path", dest="derivation_path", default=default_derivation_path)
output_group.add_argument( "-p", "--xprv", help="Generate xprv (default is xpub)", action="store_true", dest="output_xprv" )

args = parser.parse_args()

master_key = args.master_key
if args.gen_master:
    key_type = args.gen_master if args.gen_master != "p2pkh" else "standard"
    entropy = ecdsa.util.randrange( pow( 2, entropy_size * 8 ) )
    entropy_in_bytes = entropy.to_bytes( entropy_size , sys.byteorder )
    xprv,xpub = bitcoin.bip32_root( entropy_in_bytes, key_type )
    master_key = xprv
elif args.master_key == "-":
    master_key = sys.stdin.readline().strip()

derivation_path = args.derivation_path if args.derivation_path != "m" else "m/"
if bitcoin.is_bip32_derivation( derivation_path ):
    try:
        xprv,xpub = bitcoin.bip32_private_derivation( master_key,"m/", derivation_path )    
        sys.stderr.write( "Derivation Path: {}\n".format( derivation_path ) )
        if args.output_xprv:
            print( xprv )
        else:
            print( xpub )
    except BaseException:
        print( "Invalid Master Key" )
else:
    print( "Incorrect derivation path" )

