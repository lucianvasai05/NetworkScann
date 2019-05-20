  Programul ofera posibilitatea vizualizarii header-elor interceptate pe un anumit device disponibil  ce poate fi selectat de
catre utilizator

  In urma interceptarii,programul va extrage toate datele continute in header si se vor printa automat in log.txt pentru vizualizare
-->functia process_packet = contorizeaza toate pachetele si le distribuie in functie de protocoale cu afisare in timp real 
-->functia print_ethernet_header = contine o structura de tip ethhdr si printeaza adresa ip sursa/destinatie,protocol
-->functia print_ip_header = contine o structura de tip iphdr si printeaza adresa ip sursa/destinatie,protocol,suma_control,versiune,TTL
-->functia print_tcp_header = contine o structura de tip tcphdr si una iphdr - afiseaza continul din header
-->functia print_udp_header = contine o structura de tip udp hdr si una iphdr -afiseaza continul din header
-->functia print_icmp_header = contine o structura de tip icmp  hdr si una iphdr- afiseaza continul din header



In continuare urmeaza sortarea datelor si expunerea acestora pentru vizualizarea posibilelor anomalii aparute in timpul interceptarii!
Revenim....
