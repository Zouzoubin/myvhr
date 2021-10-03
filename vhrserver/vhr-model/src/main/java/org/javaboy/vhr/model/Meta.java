package org.javaboy.vhr.model;

import java.io.Serializable;

/**
 *
 */
public class Meta implements Serializable {
    private Boolean keepAlive;//状态

    private Boolean requireAuth;//是否需要认证

    public Boolean getKeepAlive() {
        return keepAlive;
    }

    public void setKeepAlive(Boolean keepAlive) {
        this.keepAlive = keepAlive;
    }

    public Boolean getRequireAuth() {
        return requireAuth;
    }

    public void setRequireAuth(Boolean requireAuth) {
        this.requireAuth = requireAuth;
    }
}
