echo $FLAG > /flag
chmod 777 /flag
export FLAG=flag_not_here
FLAG=flag_not_here
rm -f /flag.sh

apache2-foreground