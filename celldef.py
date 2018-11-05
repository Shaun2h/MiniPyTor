class cell():
    _Types = ["AddCon", "Req", "ConnectResp", "FAILED", "relay connect","relay","giveDirect","getDirect"]

    def __init__(self, payload, IV=None, salt=None, signature=None, Type =None):
        self.payload = payload
        self.signature = signature
        self.IV = IV  # save the IV since it's a connection cell.
        self.salt = salt
        if (Type != None):
            if (Type == "failed"):
                self.type = self._Types[3]  # indicates failure
            elif(Type =="relay connect"):
                self.type = self._Types[4]  # indicates to make a connection to a new server.
            elif (Type == "AddCon"):
                self.type = self._Types[0]  # is a connection request. so essentially some key is being pushed out here.
            elif (Type == "Req"):
                self.type = self._Types[1]  # is a plain request. so essentially some key is being pushed out here.
            elif (Type == "ConnectResp"):
                self.type = self._Types[2]  #is a response to a connection
            else:
                self.type = self._Types[5] #indicates relay

