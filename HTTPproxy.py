#Author    : Aidan Wilde
#Class     : Computer Networks CS 4480
#Assignment: PA-1 Final
#Date      : March 4, 2023
# Code implements a proxy server which should handle mutliple clients, caching, and domain blocking.

# Place your imports here
import signal
import sys
import re
import socket
import threading
from urllib.parse import urlsplit
from optparse import OptionParser

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
	sys.exit(0)

# Handles URLs which should be read as a command by the proxy
def checkSettingsConfig(urlPath):
    global cacheEnabled
    global blocklistEnabled
    #Each if statement checks if url is a command and executes it appropriatly if it is
    if(urlPath == "/proxy/cache/enable") :
        cacheEnabled = True
        return True

    if(urlPath == "/proxy/cache/disable") :
        cacheEnabled = False
        return True

    if(urlPath == "/proxy/cache/flush") :
        cache.clear()
        return True

    if(urlPath == "/proxy/blocklist/enable") :
        blocklistEnabled = True
        return True

    if(urlPath == "/proxy/blocklist/disable") :
        blocklistEnabled = False
        return True

    if "/proxy/blocklist/add/" in urlPath :
        stringToAdd = urlPath[21:]
        port = 80
        #sort the port from the hostname
        if ":" in stringToAdd :
            index = stringToAdd.index(':') + 1
            port = stringToAdd[index:]
            port = int(port)
            stringToAdd = stringToAdd[:index-1]
        
        #add hostname and port to the hostname
        blocklist.add(stringToAdd)
        blockListPort.update({stringToAdd: port})
        return True

    if "/proxy/blocklist/remove/" in urlPath :
        stringToRemove = urlPath[24:]
        port = 80
        #sort the port form the hostname
        if ":" in stringToRemove :
            index = stringToRemove.index(':') + 1
            port = stringToRemove[index:]
            port = int(port)
            stringToRemove = stringToRemove[:index-1]
        
        #add hostname and port to the hostname
        if(blocklist.__contains__(stringToRemove)) :
            blocklist.remove(stringToRemove)
            del blockListPort[stringToRemove]
        return True

    if(urlPath == "/proxy/blocklist/flush") :
        blocklist.clear()
        return True
    return False

#After recieving response from server, determines if cache should be updated or not
#if so, updates the cache and returns true, if 304 is returned, return false
def cacheManagement(remote_response, fromClient) :
    response = remote_response.decode()

    #Check if the response was modified
    if "304 Not Modified" in response:
        return False

    if "200 OK" in response :
        #If response was recorded, get the date out of the response
        index = response.index('Last-Modified: ')
        dateAndRest = response[index:]
        indexrn = dateAndRest.index('\r\n')
        date = dateAndRest[15:indexrn]
        cacheDate.update({fromClient: date})
        cache.update({fromClient: remote_response})
        return True
    else :
        return True 

    
# Parses the client request, in a way to send to the server, handles
#conditional GET messages based on the status and contents of the cache
def parse(clientRequest) :
    
    clientRequest = clientRequest.decode()
    
    #indicated whether we want to do a cond get or regular get
    condGet = False
    if(cacheEnabled) :
        if(cache.__contains__(clientRequest)) : 
            condGet = True

    port = 80
    #bool to check for 501 error
    fiveOOne = False
    fourHundred = False

    #check first line for proper GET and HTTP/1.0
    splitByLine = clientRequest.split("\r\n")

    firstLine = splitByLine[0]

    firstLine = firstLine.split(" ")
    #check for proper GET
    if not (firstLine[0] == "GET") :
        fiveOOne = True

    #check for proper HTTP/1.0
    if(len(firstLine) < 3 or firstLine[2] != "HTTP/1.0") :
        fourHundred = True
    
    #Check for a proper URL
    url = firstLine[1]
    parsedURL = urlsplit(url)

    #check if the given URL is a cache/domain blocking command
    if(checkSettingsConfig(parsedURL.path)) :
        response = "200 OK\r\n\r\n"
        return response.encode(), "hostName", -1
        
    #check for protocol
    if(parsedURL.scheme == "") :
        fourHundred = True

    #check for hostname
    if(parsedURL.netloc == "") :
        fourHundred = True

    #check for protocol
    if(parsedURL.path == "") :
        fourHundred = True

    #set hostname
    hostName = parsedURL.netloc

    #check for a new port number, if so get a new netloc
    if ":" in parsedURL.netloc :
        increment = parsedURL.netloc.index(":")
        port = int(parsedURL.netloc[increment + 1:])
        hostName = parsedURL.netloc[:increment]

    #blocklist check against the hostname and port
    if(blocklistEnabled):
        for word in blocklist :
            if hostName in word or word in hostName: #check to see if hostName is on banned domains
                bannedPort = blockListPort.get(word)
                if (port == bannedPort) : #check that ports match
                    response = "403 Forbidden\r\n\r\n"
                    return response.encode(), hostName, -1
    

    #Checks if all headers are properly formatted via regex
    #If header is Connection add it to the headers string, if header
    #is Connection, do not add it, add it later
    i = 1
    headers = ""
    while(i < len(splitByLine) ) : 
        currentLine = splitByLine[i]
        p = re.compile("^[^\s:]+: .*$")
        connection = re.compile("Connection")
        if not (currentLine == "") :
            if(p.match(currentLine)) :
                if not (connection.match(currentLine)) :
                    headers += currentLine + "\r\n"
            else :
                fourHundred = True
        i += 1
    
    #Handle all of the bad inputs
    if(fourHundred) :
        errorCode = "HTTP/1.0 400 Bad Request\r\n\r\n" 
        return errorCode.encode(), hostName, -1
    if(fiveOOne) :
        errorCode = "HTTP/1.0 501 Not Implemented\r\n\r\n"
        return errorCode.encode(), hostName, -1
    
    #make the first line of the Get request
    returnFirstLine = firstLine[0] + " " + parsedURL.path + " " + firstLine[2] + "\r\n"

    #make second line
    returnSecondLine = "Host: " + str(hostName) + "\r\n"

    #make connection line
    returnThirdLine = "Connection: close\r\n"

    #add If-Modified-Since if we are doing a conditional get
    if(cacheEnabled) :
        if(condGet) :
            returnThirdLine += "If-Modified-Since: " + cacheDate.get(clientRequest) + "\r\n"

    #make header line
    returnFourthLine = headers + "\r\n"

    returnLine = returnFirstLine + returnSecondLine + returnThirdLine + returnFourthLine

    return returnLine.encode(), str(hostName), int(port)
    
#Method which handles the connection of each client given it's socket and a persistent connection
#Method is called for each client which attempts to connect
def handleClient(clientSocket) :
  
    #set to none
    remoteSocket = None

    while True:
        #Receive all the data from client and forward it to remote server
        fromClient = b''
        while True :
            temp = clientSocket.recv(4096)
            fromClient += temp
            if(fromClient.endswith(b'\r\n\r\n')) :
                break
        
        #If we recieve nothing from parse message, leave and disconnect
        fromClientParsed = parse(fromClient)
        if(fromClientParsed is None) :
            break
        
        #if port is set to -1, treat it as a flag and send the error message to the client
        toSendToRemote, host, port = parse(fromClient)
        if(port == -1) :
            clientSocket.sendall(toSendToRemote)
            clientSocket.close()
            break

        #Send the data to the remote server
        remoteSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remoteSocket.connect((host, port))
        remoteSocket.sendall(toSendToRemote)


        #Recieve data back from the remote server
        remote_Response = b''
        while True :
            temp = remoteSocket.recv(4096)
            remote_Response += temp
            if(len(temp) < 1) :
                break

        #manage the cache based on the response    
        if(cacheEnabled) :
            if not cacheManagement(remote_Response, fromClient.decode()) :
                #source from the cache
                remote_Response = cache.get(fromClient.decode())

        #Send back to client
        clientSocket.sendall(remote_Response)
        break

    clientSocket.close()
    if remoteSocket is not None :
        remoteSocket.close()


# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

#create our cache and blocklist data structures and booleans
cache = {}
cacheDate = {}
blockListPort = {}
blocklist = set()
cacheEnabled = False
blocklistEnabled = False

port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

#Create our proxys socket
pSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
pSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

#Connect to incoming traffic
pSocket.bind((address, port))

pSocket.listen()

while True : 
    #Connect to socket and designate a thread to handle the connection
    clientSocket, clientAddr = pSocket.accept()
    thread = threading.Thread(target=handleClient, args=(clientSocket,))
    thread.start()



