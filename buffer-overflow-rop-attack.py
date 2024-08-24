!pip install python-ptrace lief capstone

!wget -O server-sample.zip https://github.com/chiache/csce713-assignments/raw/master/lab2/server-sample.zip
!unzip -o server-sample.zip

!killall -9 -q server

import subprocess
import time

p = subprocess.Popen('./server', shell=False, stderr=subprocess.PIPE, universal_newlines=True)

# Wait for server to start
while True:
  if "Server started" in p.stderr.readline(): break

time.sleep(1)

import requests
from IPython.core.display import display, HTML

r = requests.get('http://127.0.0.1:8000', stream=True)
display(HTML(r.text))

import requests
from IPython.core.display import display, HTML

# TODO: Manipulate the following command to crash the server
r = requests.get('http://127.0.0.1:8000/', stream=True)
display(HTML(r.text))

!killall -9 -q server

import ptrace.debugger
from ptrace.debugger import NewProcessEvent, ProcessSignal
from resource import getpagesize
from logging import info
import signal

PGSIZE = getpagesize()

def trace_segfault(pid):
  debugger = ptrace.debugger.PtraceDebugger()
  debugger.traceFork()
  process = debugger.addProcess(pid, False)
  print("Continue process execution")
  process.cont()
  print("Wait next process event...")
  while True:
      event = debugger.waitProcessEvent()
      p = event.process
      if isinstance(event, NewProcessEvent):
        print("New process created: pid = %d" % p.pid)
        p.cont()
      elif isinstance(event, ProcessSignal):
        print("%s in process %d" % (signal.strsignal(event.signum), p.pid))
        print("EIP: %08x" % p.getreg("rip"))
        print("ESP: %08x" % p.getreg("rsp"))
        print("EBP: %08x" % p.getreg("rbp"))
        print("EAX: %08x" % p.getreg("rax"))
        print("EBX: %08x" % p.getreg("rbx"))
        print("ECX: %08x" % p.getreg("rcx"))
        print("EDX: %08x" % p.getreg("rdx"))
        print("Stack (high to low):")
        sp = p.getStackPointer()
        for va in range(sp + 24, sp - 40, -8):
            try:
                value = p.readWord(va)
                if va == sp: mark = " <- ESP"
                else: mark = ""
                print("%08x: %08x"   % (va + 4, value >> 32))
                print("%08x: %08x%s" % (va,     value & 0xFFFFFFFF, mark))
            except:
                pass
        break
  debugger.quit()

  !killall -9 -q server

import subprocess
import multiprocessing
import time
import socket
from IPython.core.display import display, HTML

def trace_server():
  p = subprocess.Popen('./server', shell=False, stderr=subprocess.PIPE, universal_newlines=True)

  # Wait for server to start
  while True:
    if "Server started" in p.stderr.readline(): break

  trace_segfault(p.pid)

proc = multiprocessing.Process(target=trace_server)
proc.start()

time.sleep(1)

# TODO: Manipulate the following command to crash the server
try:
  r = requests.get('http://127.0.0.1:8000/', stream=True)
  display(HTML(r.text))
except:
  pass

# Kill the server
proc.terminate()
proc.join()


import lief
from capstone import *
import os

# Parse the ELF binary
binary = lief.parse("server")

code_section = binary.get_section('.text')
code_start = code_section.virtual_address
code_end = code_start + code_section.size
print("Code section: %08x - %08x" % (code_start, code_end))

# Read the code
fd = os.open('server', os.O_RDONLY)
code = os.pread(fd, code_section.size, code_section.file_offset)

# Parse the instruction within a specific range
search_range = (0x0, 0x0) # TODO: Update the range

md = Cs(CS_ARCH_X86, CS_MODE_32)
for insn in md.disasm(code[search_range[0]-code_start:search_range[1]-code_start], search_range[0]):
    print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))


import lief

binary = lief.parse("server")

# TODO: Find out the address of printf (Hint: Use lief API)
printf_addr = ...
print("Address of printf = %08x" % (printf_addr))

# TODO: Find out the address of secret (Hint: Use lief API)
secret_addr = ...
print("Address of secret = %08x" % (secret_addr))

data_section = binary.get_section('.rodata')
data_start = data_section.virtual_address
data_end = data_start + data_section.size
print("(RO) Data section: %08x - %08x" % (data_start, data_end))

fd = os.open('server', os.O_RDONLY)
data = os.pread(fd, data_section.size, data_section.file_offset)

# TODO: Search for '%s' in the data and add the ponters into a list
format_strings = []

def find_null_terminated_str(x, start):
  s = ''
  for i in range(len(x)):
    if x[start+i] == 0:
      break
    s += chr(x[start+i])
  return s.encode('unicode_escape')

print("Possible format strings:")
for str_addr in format_strings:
  print("%08x: %s" % (str_addr, find_null_terminated_str(data, str_addr - data_start)))


!killall -9 -q server

import subprocess
import multiprocessing
import time
import socket
from IPython.core.display import display, HTML

def trace_server():
  p = subprocess.Popen('./server', shell=False, stderr=subprocess.PIPE, universal_newlines=True)

  # Wait for server to start
  while True:
    if "Server started" in p.stderr.readline(): break

  trace_segfault(p.pid)

proc = multiprocessing.Process(target=trace_server)
proc.start()

time.sleep(1)

# Let's use socket instead of requests
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 8000))

# TODO: Manipulate the following command to crash the server
req = "GET /".encode() + bytearray() + " HTTP/1.1\r\nConnection: close\r\n\r\n".encode()
client_socket.sendall(req)

# Wait for the response and display it
r = client_socket.recv(4096)
client_socket.close()
display(HTML(r.decode()))

# Kill the server
proc.terminate()
proc.join()


import lief
from capstone import *
import os

binary = lief.parse("server")

code_section = binary.get_section('.text')
code_start = binary.imagebase + code_section.offset
code_end = code_start + code_section.size

fd = os.open('server', os.O_RDONLY)
code = os.pread(fd, code_section.size, code_section.file_offset)

md = Cs(CS_ARCH_X86, CS_MODE_32)
insn = next(md.disasm(code, code_start))
print("First instruction:")
print("%08x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
print()

# TODO: find all the RET instructions and put them into a list
ret_insns = []

# Do not change the code below
print("Print all the RET instructions:")
for insn in ret_insns:
  assert insn.mnemonic == 'ret'
  print("%08x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))



MAX_BYTES_PER_GADGET = 8 # Not counting the RET instruction

# TODO: find all the gadgets and put them into a list.
# Each gadget shall be a list of instructions, ended with RET.
# Optionally, you can ignore repeated gadgets (i.e., sequences that have already showed up).
gadgets = []

# Do not change the code below
print("Print all the gadgets:")
n = 1
for gadget in gadgets:
  print("Gadget #%d:" % n)
  n += 1
  assert len(gadget) > 0
  assert gadget[-1].mnemonic == 'ret'
  addr = gadget[0].address
  for insn in gadget:
    assert insn.address == addr
    addr += insn.size
    print("%08x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))


n = 1
for gadget in gadgets:
  # TODO: determine if this gadget contains a call to `__kernel_vsyscall`
  is_syscall_gadget = False

  if is_syscall_gadget:
    print("Syscall Gadget #%d:" % n)
    n += 1
    for insn in gadget:
      print("%08x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))


n = 1
for gadget in gadgets:
  # TODO: determine if this gadget contains XOR
  is_xor_gadget = False

  if is_xor_gadget:
    print("XOR Gadget #%d:" % n)
    n += 1
    for insn in gadget:
      print("%08x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))


import lief

binary = lief.parse("server")
data_section = binary.get_section('.rodata')
data_start = data_section.virtual_address
data_end = data_start + data_section.size

fd = os.open('server', os.O_RDONLY)
data = os.pread(fd, data_section.size, data_section.file_offset)

# TODO: Search for './public' in the data
path_strings = []

def find_null_terminated_str(x, start):
  s = ''
  for i in range(len(x)):
    if x[start+i] == 0:
      break
    s += chr(x[start+i])
  return s.encode('unicode_escape')

print("Possible path strings in ./public:")
for str_addr in path_strings:
  print("%08x: %s" % (str_addr, find_null_terminated_str(data, str_addr - data_start)))



!killall -9 -q server

import subprocess
import multiprocessing
import time
import socket
from IPython.core.display import display, HTML

def trace_server():
  p = subprocess.Popen('./server', shell=False, stderr=subprocess.PIPE, universal_newlines=True)

  # Wait for server to start
  while True:
    if "Server started" in p.stderr.readline(): break

  trace_segfault(p.pid)

proc = multiprocessing.Process(target=trace_server)
proc.start()

time.sleep(1)

# Let's use socket instead of requests
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 8000))

# TODO: Manipulate the following command to crash the server
req = "GET /".encode() + bytearray() + " HTTP/1.1\r\nConnection: close\r\n\r\n".encode()
client_socket.sendall(req)

# Wait for the response and display it
r = client_socket.recv(4096)
client_socket.close()
display(HTML(r.decode()))

# Kill the server
proc.terminate()
proc.join()


!killall -9 -q server

import subprocess
import time
import requests
from IPython.core.display import display, HTML

p = subprocess.Popen('./server', shell=False, stderr=subprocess.PIPE, universal_newlines=True)

# Wait for server to start
while True:
  if "Server started" in p.stderr.readline(): break

time.sleep(1)

# TODO: Change the URL to access the created symbolic link
r = requests.get('http://127.0.0.1:8000/', stream=True)
display(HTML(r.text))