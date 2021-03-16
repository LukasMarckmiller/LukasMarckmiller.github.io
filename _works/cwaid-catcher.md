---
title: cwaid-catcher
category: GitHub
category_slug: design
type: content
image: assets/img/works/cwa.png
button_url: https://github.com/CWAId-Catcher-Team/cwaid-catcher
---

CWAid-catcher is a project which tries to analyse the german Corona-Warn-App (CWA) spread and usage among citizens. This project is splitted into two parts. One part is the code for a ESP32 sensor, which catches BLE Beacons from the Exposure Notification Framework that are emitted if a person has an active Corona-Warn-App installed on its smartphone. The other part is the evaluation framework, that matches the collected Beacons (also called IDs in our project) to Temporary Exposure Keys (TEK) uploaded to the CWA server, to determine if one of the collected Beacons corresponds to a TEK, which means that the Beacon belongs to a infected person. Overall, the CWA ecosystem is mimicked with our project, such that you can evaluate the CWA by yourself with ESP32 sensors. Even without access to ESP32 sensors and without collecting Beacons, you can still evaluate some data, like the amount of new warnings uploaded to the CWA server each date.