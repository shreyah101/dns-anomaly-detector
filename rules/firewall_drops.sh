#!/usr/bin/env bash
# Linux iptables / Netfilter Automated Drop Script
# Generated on 2026-10-31 20:41:44
# Matches plaintext UDP DNS only; use RPZ for resolver policy enforcement.
set -e

echo '[+] Applying DNS Anomaly Firewall Drops...'
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|166535366132616435663863373634303366383765396608633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|166535366132616435663863373634303366383765396608633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0c34613966613736653561626605657866696c03746f7000|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0c34613966613736653561626605657866696c03746f7000|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0c3461316563323566386231320364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0c3461316563323566386231320364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|18363134303538336330333436633562653264396239363132046576696c036e657400|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|18363134303538336330333436633562653264396239363132046576696c036e657400|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0c38663361323936393033653208633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0c38663361323936393033653208633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|176336643832303564633364336231623563626236376665087068697368696e6702636e00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|176336643832303564633364336231623563626236376665087068697368696e6702636e00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0f383339336436336332623364346161046576696c036e657400|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0f383339336436336332623364346161046576696c036e657400|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|14756b7232626679347832386e6a69667931373070076461726b7765620362697a00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|14756b7232626679347832386e6a69667931373070076461726b7765620362697a00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|096973797073636a316d06626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|096973797073636a316d06626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|097336353274376a356f076461726b7765620362697a00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|097336353274376a356f076461726b7765620362697a00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1261636439346266633130303466616239333106626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1261636439346266633130303466616239333106626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1666613661316462373836386135353138313034393434076461726b7765620362697a00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1666613661316462373836386135353138313034393434076461726b7765620362697a00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|146771656571347a7038676a6a75366e33377236360674756e6e656c02696f00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|146771656571347a7038676a6a75366e33377236360674756e6e656c02696f00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0b70716130636e306b31367a08633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0b70716130636e306b31367a08633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1161656c6878643933356765316b676f6c6705657866696c03746f7000|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1161656c6878643933356765316b676f6c6705657866696c03746f7000|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1074666f746a706e346d366978726b323906626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1074666f746a706e346d366978726b323906626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1565336563636639623965653265323734393930663206626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1565336563636639623965653265323734393930663206626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|133637323532386334303932363135613435386206626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|133637323532386334303932363135613435386206626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|16636538326166633830303362303338376130623932610364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|16636538326166633830303362303338376130623932610364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|14746b763130626362696f6e31316b6d3679626c33076d616c77617265036f726700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|14746b763130626362696f6e31316b6d3679626c33076d616c77617265036f726700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|13746236707762777270746e76336e646832656a046576696c036e657400|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|13746236707762777270746e76336e646832656a046576696c036e657400|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|12663938643134633165373766313039616433087068697368696e6702636e00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|12663938643134633165373766313039616433087068697368696e6702636e00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|14366132346436366666343032666233656562303808633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|14366132346436366666343032666233656562303808633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1431343834663234316264343665393366633437380674756e6e656c02696f00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1431343834663234316264343665393366633437380674756e6e656c02696f00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|14366436346639323962323737326137393839633706626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|14366436346639323962323737326137393839633706626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0d6d7679383736376a6733783438076d616c77617265036f726700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0d6d7679383736376a6733783438076d616c77617265036f726700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1037313365633431626232386131313064046576696c036e657400|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1037313365633431626232386131313064046576696c036e657400|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0b65726e356c6368356536700364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0b65726e356c6368356536700364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|143763613136353333643863366430353334623265046576696c036e657400|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|143763613136353333643863366430353334623265046576696c036e657400|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0c62303661326633316266633805657866696c03746f7000|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0c62303661326633316266633805657866696c03746f7000|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|13636977693966696f386d67306471683970733808633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|13636977693966696f386d67306471683970733808633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|17363138653732326661353865363364393732613834663705657866696c03746f7000|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|17363138653732326661353865363364393732613834663705657866696c03746f7000|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|10356664643365643736643366653430330364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|10356664643365643736643366653430330364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1032333765356261343033333835613931076261647369746503636f6d00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1032333765356261343033333835613931076261647369746503636f6d00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1034333431323035653564326266333962087068697368696e6702636e00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1034333431323035653564326266333962087068697368696e6702636e00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1430647a6262683570636769656361346a356e6e710364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1430647a6262683570636769656361346a356e6e710364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0834613731776a646f076461726b7765620362697a00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0834613731776a646f076461726b7765620362697a00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|15393437386237356637333864653165313965383836076461726b7765620362697a00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|15393437386237356637333864653165313965383836076461726b7765620362697a00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0f343138613665653334343839613530087068697368696e6702636e00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0f343138613665653334343839613530087068697368696e6702636e00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0979613832307a366869087068697368696e6702636e00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0979613832307a366869087068697368696e6702636e00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|14616e7935766368736a6566326d34386d79686b68076461726b7765620362697a00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|14616e7935766368736a6566326d34386d79686b68076461726b7765620362697a00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|14663765326538313934303130366439613161373105657866696c03746f7000|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|14663765326538313934303130366439613161373105657866696c03746f7000|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0e3364373464303331363862323965076261647369746503636f6d00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0e3364373464303331363862323965076261647369746503636f6d00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0b623739376137643265343005657866696c03746f7000|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0b623739376137643265343005657866696c03746f7000|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|143834393862306632616230376132313034323163087068697368696e6702636e00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|143834393862306632616230376132313034323163087068697368696e6702636e00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0f6e3237796639633975623630736b62076461726b7765620362697a00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0f6e3237796639633975623630736b62076461726b7765620362697a00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|133235323038373936616636393837303139393505657866696c03746f7000|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|133235323038373936616636393837303139393505657866696c03746f7000|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|133539303035346331326162666133346238303806626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|133539303035346331326162666133346238303806626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|09717a36393863746f3306626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|09717a36393863746f3306626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|143234356336396431376162303561323063323835076d616c77617265036f726700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|143234356336396431376162303561323063323835076d616c77617265036f726700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0a633636636230353534310364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0a633636636230353534310364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0f61353439613033613961336539313306626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0f61353439613033613961336539313306626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|13366e697a6d7a776664626d62796b6a306962640674756e6e656c02696f00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|13366e697a6d7a776664626d62796b6a306962640674756e6e656c02696f00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1439636464363666393330373864333135383933340674756e6e656c02696f00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1439636464363666393330373864333135383933340674756e6e656c02696f00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1864353062316130643633393139653565363433343763356408633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1864353062316130643633393139653565363433343763356408633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|10687278666830753538706b346d6a6b6b05657866696c03746f7000|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|10687278666830753538706b346d6a6b6b05657866696c03746f7000|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|136c6f79676e6f656b737379696f616b30797676076461726b7765620362697a00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|136c6f79676e6f656b737379696f616b30797676076461726b7765620362697a00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1866306363336431323830656234333363623666623335613506626f746e657402707700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1866306363336431323830656234333363623666623335613506626f746e657402707700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0c7932766a333762323232736608633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0c7932766a333762323232736608633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1366363532797232353564696a7861333569693308633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1366363532797232353564696a7861333569693308633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|117178613365337536316d707a67613864330364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|117178613365337536316d707a67613864330364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|1237316238376564333537313235623733616408633273657276657202727500|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|1237316238376564333537313235623733616408633273657276657202727500|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|12663532303061396464366331343034326466076d616c77617265036f726700|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|12663532303061396464366331343034326466076d616c77617265036f726700|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|097176316874357a38620364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|097176316874357a38620364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|0c3130303261346331313564660364676102746b00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|0c3130303261346331313564660364676102746b00|' --algo bm -j DROP
iptables -I OUTPUT -p udp --dport 53 -m string --hex-string '|143336383536373464376437336164333830386666076261647369746503636f6d00|' --algo bm -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD -p udp --dport 53 -m string --hex-string '|143336383536373464376437336164333830386666076261647369746503636f6d00|' --algo bm -j DROP
echo '[+] All anomalous DNS drop rules applied.'