#!/bin/bash
#vless (Wegare)
route="$(route | grep -i 8.8.8.8 | head -n1 | awk '{print $2}')" 
route2="$(route | grep -i 10.0.0.2 | head -n1 | awk '{print $2}')" 
echo $route
	if [[ -z $route2 ]]; then
		   printf '\n' | vless
           exit
   elif [[ -z $route ]]; then
           printf '\n' | vless
           exit
	fi
