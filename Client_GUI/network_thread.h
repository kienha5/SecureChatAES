#pragma once
// asInitiator = true  → "Start E2EE Session" (phía A)
// asInitiator = false → "Wait for Session"   (phía B)
void startNetworkThread(bool asInitiator);

void startAutoWait();