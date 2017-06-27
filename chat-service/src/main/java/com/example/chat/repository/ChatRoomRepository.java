/*
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.chat.repository;

import com.example.chat.Room;
import org.omg.CosNaming.NamingContextPackage.NotFound;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.stream.Stream;

/**
 * Created by rayt on 6/27/17.
 */
public class ChatRoomRepository {
  ConcurrentHashMap<String, Room> rooms = new ConcurrentHashMap<>();

  public Room findRoom(String name) {
    return rooms.get(name);
  }

  public Room save(Room room) throws AlreadyExistsException {
    Room previous = rooms.putIfAbsent(room.getName(), room);
    if (previous != null) {
      throw new AlreadyExistsException("Room " + room.getName() + " already exists");
    }
    return room;
  }

  public Room delete(Room room) throws NotFoundException {
    room = rooms.remove(room);
    if (room != null) {
      throw new NotFoundException("Room " + room.getName() + " was not found");
    }
    return room;
  }

  public Stream<Room> getRooms() {
    return rooms.values().stream();
  }
}