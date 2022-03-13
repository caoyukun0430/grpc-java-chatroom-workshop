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

package com.example.chat.grpc;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.grpc.Context;
import io.grpc.Metadata;

import static io.grpc.Metadata.ASCII_STRING_MARSHALLER;

/**
 * Created by rayt on 10/6/16.
 */
/**
 * Effectively, all metadata key/value pairs are transmitted via HTTP/2 headers.
 * All Metadata are strongly typed and keyed. That means, rather than using a string as a key you pass into a Map, you have to create a Metadata Key.
 * However it is limited because it only text or something that be serialized into text.  As well it is not directly accessible from server stubs.  This is a problem for example if the server stub needs to get the JWT token for validation.
* */
public class Constant {
  // TODO Add a JWT_METADATA_KEY
  public static final Metadata.Key<String> JWT_METADATA_KEY =
          Metadata.Key.of("jwt", ASCII_STRING_MARSHALLER);
  // TODO Add a JWT Context Key
  public static final Context.Key<DecodedJWT> JWT_CTX_KEY = Context.key("jwt");
  public static final Context.Key<String> USER_ID_CTX_KEY = Context.key("userId");
}
