![psn logo](https://github.com/vyv-ca/psn-cpp/blob/master/doc/psn-logo.png)

# An Open Protocol for On-Stage, Live 3D Position Data

Initially developed as a means for [**VYV**](https://www.vyv.ca)'s [**Photon**](https://www.vyv.ca/products/photon/) Media Server to internally communicate the position of freely-moving projection surfaces, [**PosiStageNet**](https://www.posistage.net/) became an open standard through a close collaboration between [**VYV**](https://www.vyv.ca) and [**MA Lighting**](https://www.malighting.com/), makers of the world-reknowned [**GrandMA2**](https://www.malighting.com/grandma2/) lighting console.

The result is a combined positioning and lighting system that allows for effects of an unparalleled scale, where large numbers of moving lights can precisely follow multiple performers on stage. The protocol’s applications do not stop at lighting – sound designers can use its data to accurately pan sound effects and music automatically according to the action on stage, and automation operators can obtain another level of feedback on the position of motor-driven stage elements – or even set targets. And that’s just the start; the applications of 3D stage positioning systems are only beginning to be explored.

If you have implemented [**PosiStageNet**](https://www.posistage.net/) in your system and would like to be mentioned on the website, or you have used [**PosiStageNet**](https://www.posistage.net/) for a project and would like to submit material for our Projects Showcase, or for other enquiries, please contact us at **info@posistage.net**

# Wireshark Dissector

This package contains a Wireshark dissector for the PosiStageNet protocol.

# Usage

Copy the Lua dissector file to the Wireshark personal plugins folder. Find this folder by looking in Help > About Wireshark > folders > Personal Lua Plugins (you may need to create this folder).
