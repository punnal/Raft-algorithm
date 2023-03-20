import json
import socket
import threading
import time
import random
import os
import sys
import math
import psutil

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import hashlib

class Node:
    def __init__(self, id, ip, port, peers, output_file=None, input_file=None):
        self.id = id
        self.ip= ip
        self.port = port
        self.peers = peers
        self.current_term = 0
        self.voted_for = None
        self.state = 'follower'
        self.leader_id = None
        self.votes_received = 0
        self.in_election = False
        self.in_flight = False
        self.commited_index = 0
        self.election_timeout = self.get_random_timeout()
        self.heartbeat_timeout = 10
        self.voted_for_term = 0
        self.counter = 0
        self.pid = os.getpid()
        self.confirmation_received = 0
        self.confirmation_from = {}

        key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048
        )

        self.private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption()
        )

        self.public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )

        self.dictionaries = {}
        self.log = []

        self.fail_dests = {}

        self.input_file = input_file
        self.output_file = output_file

        if input_file and input_file != "None":
            with open(self.input_file, 'r') as f:
                data = f.read()
            my_dict = json.loads(data)
            self.current_term = my_dict["term"]
            self.commited_index = my_dict["commited_index"]
            self.counter = my_dict["counter"]
            self.log = my_dict["logs"]
            self.dictionaries = my_dict["dictionaries"]
            self.voted_for = my_dict["voted_for"]
            self.public_key = my_dict["public_key"]
            self.private_key = my_dict["private_key"]


        self.lock = threading.Lock()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(20)

        threading.Thread(target=self.accept_connections).start()

    def get_random_timeout(self):
        return random.randint(15, 30)

    def accept_connections(self):

        while True:
            connection, address = self.sock.accept()
            threading.Thread(target=self.handle_message, args=(connection,)).start()

    def remove_peer(self, ip, port):
        for i in range(len(self.peers)):
            peer = self.peers[i]
            if peer[1] == ip and peer[2] == port:
                del self.peers[i]
                break

    def send(self, id, ip, port, message):
        if id == self.id:
            return
        message["to"] = id # seee
        print("sending", message)
        if id in self.fail_dests:
            print(id, " destination fails")
            return
        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            send_sock.connect((ip, port))
            send_sock.send(json.dumps(message).encode())
            send_sock.close()
        except Exception as e:
            print(e)
            #self.remove_peer(ip, port)

    def create_dict(self, clients, src):
        if self.id == self.leader_id:
            dict_id = str(self.counter) +"." + str(self.pid)
            self.counter += 1
            log_entry = {
                "type" : "create",
                "src" : src,
                "dict_id": dict_id,
                "members": clients,
                "public_key": "",
                "private_keys":[],
                "term": self.current_term,
                "index": len(self.log)
            }
            print(self.log)
            print("appending")
            prevhash = None
            if len(self.log) > 0:
                prevhash =  str(hashlib.sha256(str(self.log[-1]).encode('utf-8')).hexdigest())
            log_entry["prev_hash"] = prevhash
            self.log.append(log_entry)
            print(self.log)
            self.write_state()
            
            while(self.in_flight):
                time.sleep(1)

            self.in_flight = True

            while(self.in_flight):
                for peer in self.peers:
                    if peer[0] != self.id and peer[0] not in self.confirmation_from:
                        self.send_append_entry(peer, log_entry)
                timeout1 = self.heartbeat_timeout*10
                while(self.in_flight and timeout1):
                    timeout1 -= 1
                    time.sleep(1)
        else:
            name = self.leader_id
            ip = None
            port = None
            for peer in self.peers:
                if peer[0] == name:
                    ip = peer[1]
                    port = peer[2]
                    break
            if ip and port:
                self.send(name,ip, port, {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    "type": "c", 
                    "clients": clients
                    })
            
    def put_dict(self, id, key, value, src):
        if self.id == self.leader_id:
            dict_id = id
            self.counter += 1
            log_entry = {
                "type" : "put",
                "src" : src,
                "client_id": self.id,
                "dict_id": dict_id,
                "key": key,
                "value": value,
                "term": self.current_term,
                "index": len(self.log)
            }
            print(self.log)
            print("appending")
            prevhash = None
            if len(self.log) > 0:
                prevhash =  str(hashlib.sha256(str(self.log[-1]).encode('utf-8')).hexdigest())
            log_entry["prev_hash"] = prevhash
            self.log.append(log_entry)
            print(self.log)
            self.write_state()
            
            while(self.in_flight):
                time.sleep(1)

            self.in_flight = True

            while(self.in_flight):
                for peer in self.peers:
                    if peer[0] != self.id and peer[0] not in self.confirmation_from:
                        self.send_append_entry(peer, log_entry)
                #time.sleep(self.heartbeat_timeout)
                timeout1 = self.heartbeat_timeout*10
                while(self.in_flight and timeout1):
                    timeout1 -= 1
                    time.sleep(1)
        else:
            name = self.leader_id
            ip = None
            port = None
            for peer in self.peers:
                if peer[0] == name:
                    ip = peer[1]
                    port = peer[2]
                    break
            if ip and port:
                self.send(name,ip, port, {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    "type": "p", 
                    "id": id, 
                    "key": key, 
                    "value": value})
    def get_dict(self, id, key, src):
        if self.id == self.leader_id:
            dict_id = id
            self.counter += 1
            log_entry = {
                "type" : "get",
                "src" : src,
                "client_id": self.id,
                "dict_id": dict_id,
                "key": key,
                "term": self.current_term,
                "index": len(self.log)
            }
            print(self.log)
            print("appending")
            prevhash = None
            if len(self.log) > 0:
                prevhash =  str(hashlib.sha256(str(self.log[-1]).encode('utf-8')).hexdigest())
            log_entry["prev_hash"] = prevhash
            self.log.append(log_entry)
            print(self.log)
            self.write_state()
            
            while(self.in_flight):
                time.sleep(1)

            self.in_flight = True

            while(self.in_flight):
                for peer in self.peers:
                    if peer[0] != self.id and peer[0] not in self.confirmation_from:
                        self.send_append_entry(peer, log_entry)
                #time.sleep(self.heartbeat_timeout*2)
                timeout1 = self.heartbeat_timeout*10
                while(self.in_flight and timeout1):
                    timeout1 -= 1
                    time.sleep(1)
        else:
            name = self.leader_id
            ip = None
            port = None
            for peer in self.peers:
                if peer[0] == name:
                    ip = peer[1]
                    port = peer[2]
                    break
            if ip and port:
                self.send(name,ip, port, {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    "type": "g", 
                    "id": id, 
                    "key": key
                })

    def send_append_entry(self, peer, log_entry):
        name = peer[0]
        ip = peer[1]
        port = peer[2]
        prev_index = len(self.log)-1-1
        prev_term = None
        if prev_index >= 0:
            prev_term = self.log[prev_index]["term"]
        request_append_entry = {
            'from': self.id,
            'fromip': self.ip,
            'fromport': self.port,
            'type': 'append_entry',
            'log_entry': [log_entry],
            'prev_index': len(self.log)-1-1,
            'prev_term': prev_term,
            'commit_index': self.commited_index

        }
        self.send(name, ip, port, request_append_entry)
        #connection.sendall(json.dumps(request_vote_message).encode())

    def start_election(self):
        self.election_timeout = self.get_random_timeout()
        self.state = 'candidate'
        self.current_term += 1
        self.voted_for = self.id
        self.voted_for_term = self.current_term
        self.votes_received = 1
        self.in_election = True
        self.write_state()
            
        if (len(self.peers) == 0):
            self.state = 'leader'
            print("I am the leader by getting votes:", self.votes_received)
            print(math.floor((len(self.peers)+1) / 2))
            self.leader_id = self.id
            self.votes_received = 0
            self.in_election = False
            return
            
        for peer in self.peers:
            if peer[0] != self.id:
                self.send_request_vote(peer)

    
    def wait_and_start_election(self):
        while(True):
            time.sleep(1)
            if self.state != 'leader':
                while(self.election_timeout):
                    time.sleep(1)
                    self.lock.acquire()
                    self.election_timeout -= 1
                    self.lock.release()
                self.handle_timeout()
                #self.start_election()

    def send_request_vote(self, peer):
        name = peer[0]
        ip = peer[1]
        port = peer[2]
        log_entry = None
        if len(self.log) > 0:
            log_entry = self.log[-1]
        request_vote_message = {
            'from': self.id,
            'fromip': self.ip,
            'fromport': self.port,
            'type': 'request_vote',
            'candidate_id': self.id,
            'term': self.current_term,
            'log_entry': log_entry 
        }
        self.send(name, ip, port, request_vote_message)
        #connection.sendall(json.dumps(request_vote_message).encode())
        #response = connection.recv(1024)
        #response_message = json.loads(response.decode())
        #return response_message['vote_granted']
    
    def handle_heartbeat_decision(self, message):
        vote = message['entry_appended']
        if vote and self.state =='leader' and self.in_flight:
            pass
        elif not vote:
            print("Here!!!")
            log_length = message["length_entries"]
            prev_index = len(self.log)-1-(log_length+1)
            print("prev index: ", prev_index)
            prev_term = None
            if prev_index >= 0:
                prev_term = self.log[prev_index]["term"]
            if prev_index == -1:
                log_entries = self.log
            else:
                log_entries = self.log[prev_index+1:] #seeee
            request_append_entry = {
            'from': self.id,
            'fromip': self.ip,
            'fromport': self.port,
            'type': 'heartbeat',
            'leader_id': self.id,
            'term': self.current_term,
            'log_entry': log_entries,
            'prev_index': prev_index,
            'prev_term': prev_term,
            'commit_index': self.commited_index

            }
            self.send(message["from"], message["fromip"], message["fromport"], request_append_entry)

    def handle_append_decision(self, message):
        vote = message['entry_appended']
        if vote and self.state =='leader' and self.in_flight:
            self.lock.acquire()
            self.confirmation_received += 1
            self.confirmation_from[message["from"]] = 1
            self.lock.release()
            self.lock.acquire()
            if self.confirmation_received+1 > math.floor((len(self.peers)+1) / 2):
                print("I am commiting by getting accepts:", self.confirmation_received)
                print(math.floor((len(self.peers)+1) / 2))
                self.confirmation_received = 0
                self.confirmation_from = {}
                self.in_flight = False

                #commit
                self.handle_commit()

                self.write_state()
            self.lock.release()
        elif not vote:
            print("Here!!!")
            self.confirmation_from[message["from"]] = 1
            log_length = message["length_entries"]
            prev_index = len(self.log)-1-(log_length+1)
            print("prev index: ", prev_index)
            prev_term = None
            if prev_index >= 0:
                prev_term = self.log[prev_index]["term"]
            if prev_index == -1:
                log_entries = self.log
            else:
                log_entries = self.log[prev_index+1:] #seeee
            request_append_entry = {
            'from': self.id,
            'fromip': self.ip,
            'fromport': self.port,
            'type': 'append_entry',
            'log_entry': log_entries,
            'prev_index': prev_index,
            'prev_term': prev_term,
            'commit_index': self.commited_index

            }
            self.send(message["from"], message["fromip"], message["fromport"], request_append_entry)

    def varify_hash(self, a, b):
        #implement varify hash
        if len(a) > 0 and len(b) > 0:
            e1 = a[-1]
            e2 = b[0]
            prevhash =  str(hashlib.sha256(str(e1).encode('utf-8')).hexdigest())
            print(e2["prev_hash"])
            print(prevhash)
            if e2["prev_hash"] == prevhash:
                e1 = e2
                for e2 in b[1:]:
                    prevhash =  str(hashlib.sha256(str(e1).encode('utf-8')).hexdigest())
                    print(e2["prev_hash"])
                    print(prevhash)
                    if e2["prev_hash"] != prevhash:
                        return False
                    e1 = e2
                print("verified hash----")
                return True
            return False

        return True

    def handle_commit(self):

        print(self.in_flight)
        print(self.commited_index)
        print(self.log)
        if self.commited_index >= len(self.log):
            return 
        log_entry = self.log[self.commited_index]
        self.commited_index += 1
        if log_entry["type"] == "create":
            if self.id in log_entry["members"]:
                if log_entry["src"] in log_entry["members"]:
                    self.dictionaries[log_entry["dict_id"]] = {
                        "dict": {}, 
                        "members": log_entry["members"],
                        "public_key": log_entry["public_key"],
                        "private_keys":log_entry["private_keys"]
                        }
        elif log_entry["type"] == "put":
            if self.dictionaries.get(log_entry["dict_id"]):
                if self.id in self.dictionaries[log_entry["dict_id"]]["members"]:
                    if log_entry["src"] in self.dictionaries[log_entry["dict_id"]]["members"]:
                        if log_entry["client_id"] in self.dictionaries[log_entry["dict_id"]]["members"]:
                            self.dictionaries[log_entry["dict_id"]]["dict"][log_entry["key"]] = log_entry["value"]
                        else:
                            print("not a member")
        elif log_entry["type"] == "get":
            if self.dictionaries.get(log_entry["dict_id"]):
                if self.id in self.dictionaries[log_entry["dict_id"]]["members"]:
                    if log_entry["src"] in self.dictionaries[log_entry["dict_id"]]["members"]:
                        if log_entry["client_id"] in self.dictionaries[log_entry["dict_id"]]["members"]:
                            print(self.dictionaries[log_entry["dict_id"]]["dict"][log_entry["key"]])
                        else:
                            print("not a member")


    def handle_vote_decision(self, message):
        vote = message['vote_granted']
        if vote and self.state!='leader' and self.in_election:
            self.lock.acquire()
            self.votes_received += 1
            self.lock.release()
            if self.votes_received > math.floor((len(self.peers)+1) / 2):
                self.state = 'leader'
                print("I am the leader by getting votes:", self.votes_received)
                print(math.floor((len(self.peers)+1) / 2))
                self.leader_id = self.id
                self.votes_received = 0
                self.in_election = False
                return
    
    def handle_heartbeat_entry(self, sender, log_entries, message):

        if sender == self.leader_id:
            prev_index = message["prev_index"]
            prev_term = message["prev_term"]
            if prev_index > len(self.log) - 1:
                return {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    'type': 'heartbeat_decsion',
                    'entry_appended': False,
                    'length_entries': len(log_entries)
                }
            prev_entry = {}
            if prev_index >= 0:
                prev_entry = self.log[prev_index]
            if prev_index <= len(self.log) - 1 and (prev_index < 0 or prev_entry["term"] == prev_term):
                #log_entry = log_entries[0]
                what = self.varify_hash(self.log[:prev_index+1], log_entries)
                if what==False:
                    return {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    'type': 'heartbeat_decsion',
                    'entry_appended': False,
                    'length_entries': len(log_entries)
                }
                #print("varified hash")
                self.log = self.log[:prev_index+1] + log_entries
                self.election_timeout = self.get_random_timeout()
                commits = message["commit_index"]
                while(commits and self.commited_index < len(self.log)):
                    print("YOYO")
                    self.handle_commit()
                    commits -=1
                self.write_state()

                return {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    'type': 'heartbeat_decsion',
                    'entry_appended': True,
                    'length_entries': len(log_entries)
                    }
            else:
                return {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    'type': 'heartbeat_decsion',
                    'entry_appended': False,
                    'length_entries': len(log_entries)
                }
                
        else:

            return {
                'from': self.id,
                'fromip': self.ip,
                'fromport': self.port,
                'type': 'heartbeat_decsion',
                'entry_appended': False
                }

    def handle_append_entry(self, sender, log_entries, message):

        if sender == self.leader_id:
            prev_index = message["prev_index"]
            prev_term = message["prev_term"]
            if prev_index > len(self.log) - 1:
                return {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    'type': 'append_decsion',
                    'entry_appended': False,
                    'length_entries': len(log_entries)
                }
            prev_entry = {}
            if prev_index >= 0:
                prev_entry = self.log[prev_index]
            if prev_index <= len(self.log) - 1 and (prev_index < 0 or prev_entry["term"] == prev_term):
                #log_entry = log_entries[0]
                what = self.varify_hash(self.log[:prev_index+1], log_entries)
                if what==False:
                    return {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    'type': 'append_decsion',
                    'entry_appended': False,
                    'length_entries': len(log_entries)
                }
                print("varified hash")
                self.log = self.log[:prev_index+1] + log_entries
                self.election_timeout = self.get_random_timeout()
                commits = message["commit_index"]
                while(commits and self.commited_index < len(self.log)):
                    self.handle_commit()
                    commits -=1
                self.write_state()

                return {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    'type': 'append_decsion',
                    'entry_appended': True,
                    'length_entries': len(log_entries)
                    }
            else:
                return {
                    'from': self.id,
                    'fromip': self.ip,
                    'fromport': self.port,
                    'type': 'append_decsion',
                    'entry_appended': False,
                    'length_entries': len(log_entries)
                }
                
        else:

            return {
                'from': self.id,
                'fromip': self.ip,
                'fromport': self.port,
                'type': 'append_decsion',
                'entry_appended': False,
                'length_entries': len(log_entries) #seee
                }

    def handle_request_vote(self, candidate_id, candidate_term, log_entry):
        ret_false = {
                'from': self.id,
                'fromip': self.ip,
                'fromport': self.port,
                'type': 'vote_decsion',
                'vote_granted': False
                }

        if candidate_term < self.current_term:
            return {
                'from': self.id,
                'fromip': self.ip,
                'fromport': self.port,
                'type': 'vote_decsion',
                'vote_granted': False
                }
        print("voted_for: ", self.voted_for)
        if not log_entry:
            if len(self.log) > 0:
                return ret_false
        else:
            if len(self.log) == 0:
                pass
            elif log_entry["term"] < self.log[-1]["term"]:
                return ret_false
            elif log_entry["term"] == self.log[-1]["term"] and log_entry["index"] < self.log[-1]["index"]:
                return ret_false

        if self.voted_for is None or self.voted_for == candidate_id or self.voted_for_term < candidate_term:
            # Grant vote to candidate
            self.voted_for = candidate_id
            self.voted_for_term = candidate_term

            self.election_timeout = self.get_random_timeout()
            self.votes_recieved = 0
            self.in_election = False
            self.state = 'follower' #hmm 
            return {
                'from': self.id,
                'fromip': self.ip,
                'fromport': self.port,
                'type': 'vote_decsion',
                'vote_granted': True
                }

        return {
            'from': self.id,
            'type': 'vote_decsion',
            'fromip': self.ip,
            'fromport': self.port,
            'vote_granted': False
            }

    
    def send_heartbeat(self, peer):
        name = peer[0]
        ip = peer[1]
        port = peer[2]
        prev_index = len(self.log)-1
        prev_term = None
        if prev_index >= 0:
            prev_term = self.log[prev_index]["term"]
        heartbeat_message = {
            'from': self.id,
            'fromip': self.ip,
            'fromport': self.port,
            'type': 'heartbeat',
            'leader_id': self.id,
            'term': self.current_term,
            'log_entry': [],
            'prev_index': len(self.log)-1,
            'prev_term': prev_term,
            'commit_index': self.commited_index
        }
        self.send(name, ip, port, heartbeat_message)

    def wait_and_send_heartbeat(self):
        while(True):
            time.sleep(self.heartbeat_timeout)
            if self.state == "leader":
                for peer in self.peers:
                    self.send_heartbeat(peer)


    def handle_heartbeat(self, leader_id, leader_term, message):
        if leader_term >= self.current_term:
            sender = message["from"]
            ip = message['fromip']
            port = message['fromport']
            self.state = 'follower'
            self.voted_for = None
            self.leader_id = leader_id
            self.election_timeout = self.get_random_timeout()
            response = self.handle_heartbeat_entry(sender, message['log_entry'], message)
            self.send(sender, ip, port, response)

    def handle_timeout(self):
        if self.state == 'follower':
            self.state = 'candidate'
            self.start_election()
        elif self.state == 'candidate':
            self.start_election()
        else:
            # Leader should send heartbeat messages instead of timing out
            pass

    def handle_message(self, connection):
        while True:
            data = connection.recv(1024)
            time.sleep(2)
            if not data:
                break
            print(data)
            message = json.loads(data.decode())
            print("recieved", message)
            sender = message['from']
            ip = message['fromip']
            port = message['fromport']
            if message['type'] == 'request_vote':
                response = self.handle_request_vote(message['candidate_id'], message['term'], message["log_entry"])
                self.send(sender, ip, port, response)
                #connection.sendall(json.dumps(response).encode())

            elif message['type'] == 'heartbeat':
                self.handle_heartbeat(message['leader_id'], message['term'], message)
            elif message['type'] == 'vote_decsion':
                self.handle_vote_decision(message)
            elif message['type'] == 'append_entry':
                response = self.handle_append_entry(sender, message['log_entry'], message)
                #if response["entry_appended"]:
                self.send(sender, ip, port, response)
            elif message['type'] == 'append_decsion':
                self.handle_append_decision(message)

            elif message['type'] == 'heartbeat_decsion':
                self.handle_heartbeat_decision(message)

            elif message['type'] == 'c':
                self.create_dict(message["clients"], message["from"])
            elif message['type'] == 'p':
                self.put_dict(message["id"], message["key"], message["value"], message["from"])
            elif message['type'] == 'g':
                self.get_dict(message["id"], message["key"], message["from"])
            else:
            
                # TODO: Implement handling other message types
                pass
    def write_state(self):
        my_dict = {}
        my_dict["term"] = self.current_term 
        my_dict["commited_index"] = self.commited_index
        my_dict["counter"] = self.counter
        my_dict["logs"] = self.log 
        my_dict["dictionaries"] = self.dictionaries
        my_dict["voted_for"] = self.voted_for
        my_dict["public_key"] = str(self.public_key)
        my_dict["private_key"] = str(self.private_key)
        with open(self.output_file, 'w') as f:
            #print(my_dict)
            data = json.dumps(my_dict)
            f.write(data)

    def run(self):
        input("enter any string to start")

        # Election starting thread        
        threading.Thread(target=self.wait_and_start_election).start()

        # Sending heartbeat if leader
        threading.Thread(target=self.wait_and_send_heartbeat).start()

        while(True):
            cmd = input("Give Input")
            if cmd == "":
                pass
            elif cmd == "printAll":
                print("Printing Dictionary")
                for d in self.dictionaries:
                    if self.id in self.dictionaries[d]["members"]:
                        print("dictionary id: ", d)
                        if self.id in self.dictionaries[d]["members"]:
                            print(self.dictionaries[d]["dict"])
                        else:
                            print("cannot access content as not a member")
            elif cmd.split()[0] == "create":
                cmdsp = cmd.split()
                lst = cmdsp[1:]
                self.create_dict(lst, self.id)
            elif cmd.split()[0] == "put":
                cmdsp = cmd.split()
                id = cmdsp[1]
                key = cmdsp[2]
                value = cmdsp[3]
                self.put_dict(id, key, value, self.id)
                pass
            elif cmd.split()[0] == "get":
                cmdsp = cmd.split()
                id = cmdsp[1]
                key = cmdsp[2]
                self.get_dict(id, key, self.id)
                pass
            elif cmd.split()[0] == "printDict":
                cmdsp = cmd.split()
                id = cmdsp[1]
                print("Members: ", self.dictionaries[id]["members"] )
                print("Contents: ", self.dictionaries[id]["dict"] )
            elif cmd.split()[0] == "failLink":
                cmdsp = cmd.split()
                dest = cmdsp[1]
                self.fail_dests[dest] = 1
            elif cmd.split()[0] == "fixLink":
                cmdsp = cmd.split()
                dest = cmdsp[1]
                del self.fail_dests[dest]
            elif cmd.split()[0] == "failProcess":
                #store state
                self.write_state()
                #exit()
                
                psutil.Process(os.getpid()).terminate()
            elif cmd == "printState":
                print("leader", self.leader_id)
                print("term", self.current_term)
                print("commited_index", self.commited_index)
                print("counter", self.counter)
                print("logs", self.log)
                print("dictionaries", self.dictionaries)
                print("fail_links", self.fail_dests)
            elif cmd == "test1":
                self.create_dict(["a", "b", "c", "d"], self.id)
            else:
                pass

if __name__ == "__main__":
    name = sys.argv[1]
    ip = sys.argv[2]
    port = int(sys.argv[3])
    clients = sys.argv[4]
    output_file = sys.argv[5]
    input_file = sys.argv[6]
    clientlst = []
    if clients != "":
        clients = clients.split(" ")
        for c in clients:
            pair = c.split(":")
            name_ = pair[0]
            ip_ = pair[1]
            port_ = int(pair[2])
            clientlst.append([name_, ip_,  port_]) 
    n = Node(name, ip, port, clientlst, output_file, input_file)
    n.run()