# ise-change-endpointgroup-send-coa

The idea is to assign an active client using MAC or IP to an EndPointGroup in ISE and then send a CoA for this client so new AuthZ will be applied based on the new EndPointGroup assignment.

The script obtains either a client MAC or IP as a command argument and an EndPointGroup name as an optional argument. The script checks against the ISE PAN and MNT servers via API whether the client MAC or IP exists in the active session database.

If an IP is entered, script will look for the corresponding MAC from ISE.

If a MAC is entered, script will search and find the Client_id so it can be used later on to assign EndPointGroup.

If the optional arugment EndPointGroup is entered, it checks against whether this group exists. If so, it finds the corresponding EndPointGroup_id.

The client is assigned to the EndPointGroup and a CoA is sent.

Created by Felix Lai
