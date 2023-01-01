#!/usr/bin/python3
from electrum import bip32, util
import sys, datetime, argparse

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

if args.gen_master:
    key_type = args.gen_master if args.gen_master != "p2pkh" else "standard"
    entropy = util.randrange( pow( 2, entropy_size * 8 ) )
    entropy_in_bytes = entropy.to_bytes( entropy_size , sys.byteorder )
    master_key = bip32.BIP32Node.from_rootseed( seed=entropy_in_bytes, xtype=key_type )
elif args.master_key:
    try:
        master_key = bip32.BIP32Node.from_xkey( sys.stdin.readline().strip() if args.master_key == '-' else args.master_key )
    except BaseException:
        sys.exit( "Invalid master key\n" )

if args.convert:
    if args.gen_master:
        sys.exit( "Convert option cannot be used with generate master option" )
    else:
        convert_type = args.convert if args.convert !="p2pkh" else "standard"
        master_key = master_key._replace( xtype=convert_type )
        
derivation_path = args.derivation_path if args.derivation_path != "m" else "m/"
if bip32.is_bip32_derivation( derivation_path ):
	if not master_key.is_private():
		if args.output_xprv:
				sys.exit( "Cannot derive extended private key from extended public key\n" )
		if derivation_path == "m/":
			print( master_key.to_xpub() )
		else:
			try:
				xpub = master_key.subkey_at_public_derivation(  derivation_path )
				sys.stderr.write( "Derivation Path: {}\n".format( derivation_path ) )
			except BaseException:
				sys.exit( "Invalid derivation path. Private derivation is not possible with extended public keys.\n" )
			else:
				print( xpub.to_xpub() )
	else:
		try:
			derived_key = master_key.subkey_at_private_derivation( derivation_path )    
			sys.stderr.write( "Derivation Path: {}\n".format( derivation_path ) )
		except BaseException:
			sys.stderr.write( "Invalid derivation path\n" )
		else:
			if args.output_xprv:
				print( derived_key.to_xprv() )
			else:
				print( derived_key.to_xpub()  )
else:
	print( "Incorrect derivation path" )

