import pprint
from collections import namedtuple
from typing import TypedDict, Dict, Optional


class Params(TypedDict):
    name: str
    type: str


class Entry(TypedDict):
    file: str
    # assigned to, e.g. `x` in const x = function test () {}
    member_id: str
    # assigned to, e.g. `test` in const x = function test () {}
    name: Optional[str]
    params: dict
    signature: str
    doc: str


def generate_entry_id(entry: Entry):
   """Generate ID for entry."""
   return f"{entry['file']}:{entry['member_id']}"

class PackageApiIndex:
  members = Dict[str, Entry]

  def __init__(self):
    self.members = {}

  def register(self, entry: Entry):
     """
     Index entry.
     """
     entry_id = generate_entry_id(entry)
     if entry_id in self.members:
       raise Exception(f"Duplicate entry: {entry_id}")

     self.members[entry_id] = entry

  def __repr__(self):
     repr_body = "<PackageApiIndex: \n"
     for name, val in self.members.items():
        repr_body += f" Record:{name}\t\t{val["member_id"]} ({val["name"]}) w/params: {val["params"]}\n"

     return repr_body + "\n>"
