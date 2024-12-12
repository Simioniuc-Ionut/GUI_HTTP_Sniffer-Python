# GUI_HTTP_Sniffer-Python

Implementați o aplicație care implementează un sniffer de pachete HTTP. Aplicația ar
trebui să permită vizualizarea real-time a requesturilor, aplicarea de filtre pe traficul de
pachete (ex: requesturi venite de la o anumită adresă, requesturi de anumite tipuri:
GET/POST/DELETE s.a.m.d). Totodată, pentru un anume request, ar trebuie ca

userul să poată afla detalii despre requestul respectiv: headers, request mode,
payload, etc
Nu este necesar un GUI (datele se pot afișa și în consola).Trebuie sa fie totuși o
reprezentare clară a acestor date (sa se inteleaga ce anume reprezinta).
Traficul se capturează cu ajutorul bibliotecii socket iar decodarea pachetelor se va
face cu struct/ctypes
