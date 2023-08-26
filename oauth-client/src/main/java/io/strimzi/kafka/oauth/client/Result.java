/*
 * Copyright 2017-2019, Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.kafka.oauth.client;

public class Result {
    boolean status;
    String info;

    public Result() {
        this.status = false;
        this.info = null;
    }

    public Result(boolean status, String info) {
        this.status = status;
        this.info = info;
    }
}
