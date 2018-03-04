#!/usr/bin/python3
from electrum import bitcoin
import ecdsa, sys, datetime, select

def help_msg():
    print( "Usage child-xprv (xprv|xpub)" )
    print( "Master private key needs to be provided via stdin" )

if len( sys.argv ) < 2:
    help_msg()
elif sys.argv[1] == 'xprv' or sys.argv[1] == 'xpub':
    master = sys.stdin.readline().strip()
    tdate = datetime.date.today()
    account = tdate.strftime( "m/%Y'/%m'/%d'" )
    try:
        xprv,xpub = bitcoin.bip32_private_derivation( master,"m/", account )
        sys.stderr.write( "Derivation Path: {}\n".format( account ) )
        if sys.argv[1] == 'xprv':
            print( xprv, end="" )
        else:
            print( xpub, end="" )
    except BaseException:
        print( "Invalid master private key" )
        help_msg()
else:
    print( "You must specify xpub or xpry" )
    help_msg()
