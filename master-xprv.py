#!/usr/bin/python3
from electrum import bitcoin
import ecdsa, sys
def help_msg():
    print( "Usage master-xprv (standard|p2wpkh|p2wpkh-p2sh|p2wsh-p2sh|p2wsh)" )
    
key_types = [ 'standard', 'p2wpkh', 'p2wpkh-p2sh', 'p2wsh-p2sh', 'p2pkh', 'p2wsh' ]
if len( sys.argv ) < 2:
    help_msg()
elif sys.argv[1] in key_types:
    key_type = sys.argv[1] if sys.argv[1] != "p2pkh" else "standard"
    entropy_size = 32 #in bytes
    entropy = ecdsa.util.randrange( pow( 2, entropy_size * 8 ) )
    entropy_in_bytes = entropy.to_bytes( entropy_size , sys.byteorder )
    xprv,xpub = bitcoin.bip32_root( entropy_in_bytes, key_type )
    print ( xprv, end="" )
else:
    print( "Invalid key type" )
    help_msg()
