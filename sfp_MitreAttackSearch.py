# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_MitreAttackSearch
# Purpose:      SpiderFoot plug-in for search on MitreAtt&ck.
#
# Author:      José Carlos Serrano Sácnhez <fc.jc.ss@gmail.com>
#
# Created:     18/08/2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from googlesearch import search
import subprocess
class sfp_MitreAttackSearch(SpiderFootPlugin):

    meta = {
        'name': "MitreAttackSearch",
        'summary': "Perform a search on https://attack.mitre.org/",
        'flags': [""],
        'useCases': [""],
        'categories': ["Search adversary tactics and techniques based on real-world observations"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["RAW_DATA", "USERNAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DOMAIN_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            ########################
            # Insert here the code #
            ########################
            data= subprocess.run('mitresearch -q ' +eventData, shell=True, capture_output=True, text=True)
            output = str(data.stdout)
            Dominios = output.split('\n')
            if not data:
                self.sf.error("Unable to perform sfp_MitreAttackSearch on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the sfp_MitreAttackSearch on " + eventData + ": " + str(e))
            return
            
        for dominio in Dominios:
            evt = SpiderFootEvent("DOMAIN_NAME", dominio, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_MitreAttackSearch class