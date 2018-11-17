#!/usr/bin/python3
from electrum import bitcoin
import ecdsa, sys, datetime, argparse

default_derivation_path = "m/"
key_types = [ 'standard', 'p2wpkh', 'p2wpkh-p2sh', 'p2wsh-p2sh', 'p2pkh', 'p2wsh' ]
entropy_size = 32 #in bytes
    
parser = argparse.ArgumentParser( description="Generate extended keys" )

mkey_group = parser.add_mutually_exclusive_group( required=True )
mkey_group.add_argument( "-g", "--generate-master", help="Generate master private key of a given type", choices=key_types, dest="gen_master")
mkey_group.add_argument( "-m", "--master", help="provide master private key \"-\" to read from stdin", dest="master_key" )

parser.add_argument( "-c", "--convert", help="Convert provided master key to this type", choices=key_types, dest="convert" )

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

if args.convert:
    if args.gen_master:
        sys.exit( "Convert option cannot be used with generate master option" )
    else:
        convert_type = args.convert if args.convert !="p2pkh" else "standard"
        if bitcoin.is_xpub(master_key):
            xtype, depth, fingerprint, child_number, c, K_or_k = bitcoin.deserialize_xpub( master_key )
            master_key = bitcoin.serialize_xpub( convert_type, c,  K_or_k, depth, fingerprint, child_number )
        elif bitcoin.is_xprv(master_key):
            xtype, depth, fingerprint, child_number, c, K_or_k = bitcoin.deserialize_xprv( master_key )
            master_key = bitcoin.serialize_xprv( convert_type, c,  K_or_k, depth, fingerprint, child_number )
        else:
            sys.exit( "Master key is not a valid extended key" )

derivation_path = args.derivation_path if args.derivation_path != "m" else "m/"
if bitcoin.is_bip32_derivation( derivation_path ):
	if bitcoin.is_xpub(master_key):
		if args.output_xprv:
				sys.exit( "Cannot derive extended private key from extended public key\n" )
		if derivation_path == "m/":
			print( master_key )
		else:
			try:
				xpub = bitcoin.bip32_public_derivation( master_key, "m/", derivation_path )
				sys.stderr.write( "Derivation Path: {}\n".format( derivation_path ) )
			except BaseException:
				sys.exit( "Invalid derivation path. Private derivation is not possible with extended public keys.\n" )
			else:
				print( xpub )
	elif bitcoin.is_xprv( master_key ):
		try:
			xprv,xpub = bitcoin.bip32_private_derivation( master_key,"m/", derivation_path )    
			sys.stderr.write( "Derivation Path: {}\n".format( derivation_path ) )
		except BaseException:
			sys.stderr.write( "Invalid Master Key\n" )
		else:
			if args.output_xprv:
				print( xprv )
			else:
				print( xpub )
	else:
		sys.exit( "Invalid Master Key\n" )
else:
	print( "Incorrect derivation path" )

