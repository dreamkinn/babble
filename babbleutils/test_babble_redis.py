#!/usr/bin/env python3

import argparse
import docker
import os
import random
import redis
import socket
import string
import sys
from termcolor import colored

class RedisDB:

  def __init__(self, container_name, port=None):

    self.container_name = container_name
    self.port = self.start_redis(container_name, port)
    self.r = self.connect_to_redis()

  def start_redis(self, container_name, port=None):

    client = docker.from_env()

    try:
      container = client.containers.get(container_name)

      if not self.is_redis_container(container):
        print(colored("Existing container is not Redis", "red"))
        sys.exit(1)

      if not port:
        port = container.ports['6379/tcp'][0]['HostPort']

    except docker.errors.NotFound:

      if port:
        print(colored(f"Using provided port {port}", "cyan"))
      else:
        port = self.get_open_port()
        print(colored(f"Using open port {port}", "cyan"))

      print(colored(f"Creating container {container_name}", "cyan"))

      try:
        client.images.get("redis:latest")  
      except docker.errors.ImageNotFound:
        print(colored("Pulling redis image...", "yellow"))
        client.images.pull("redis:latest")

      password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
      print(colored(f"Random password stored in config file : {password}", "green"))

      with open(f"redis_config/{container_name}_pass.txt", "w") as f:
        f.write(password)

      try:
        client.containers.run(
          "redis:latest",
          name=container_name,
          detach=True,
          ports={f'6379/tcp': port},
          command=f'/bin/sh -c "redis-server --appendonly yes --requirepass {password}"' 
        )
      
      except docker.errors.ContainerError as e:
        print(colored(f"Error starting container: {e}", "red"))
        sys.exit(1)

    print(colored(f"Redis container started on port {port}", "green"))
    return port

  def get_open_port(self, start_port=6379):
    port = start_port
    while True:
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("localhost", port))
        return port
      except OSError:
        port += 1

  def is_redis_container(self, container):
    for tag in container.image.tags:
      if "redis" in tag:
        print(colored(f"Found Redis container {container.name}", "green"))
        return True
    return False
    
  def connect_to_redis(self):

    config_file = f"redis_config/{self.container_name}_pass.txt"

    if not os.path.exists(config_file):
      print(colored(f"Config file {config_file} not found", "red"))
      return

    try:
      with open(config_file) as f:
        password = f.read()

      r = redis.Redis(host='localhost', port=self.port, password=password)
      r.ping()
      print(colored("Connected to Redis successfully!", "green"))
      return r

    except redis.exceptions.AuthenticationError as err:
      print(err)
      print(colored("Authentication error connecting to Redis", "red"))

    except ConnectionRefusedError:
      print(colored("Cannot connect to Redis server", "red"))

if __name__ == "__main__":

  parser = argparse.ArgumentParser()
  parser.add_argument("-c", required=True)
  parser.add_argument("-p", type=int, default=None)
  args = parser.parse_args()

  db = RedisDB(args.c, args.p)

  # Use db.r Redis connection
