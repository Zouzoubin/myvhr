package org.javaboy.vhr.utils;

import org.javaboy.vhr.model.Hr;
import org.springframework.security.core.context.SecurityContextHolder;

/**SecurityContextHolder中持有的是当前用户的SecurityContext，
 * 而SecurityContext持有的是代表当前用户相关信息的Authentication的引用。然后赋值给当前的SecurityContext。
 * 获取当前hr的信息
 */
public class HrUtils {
    public static Hr getCurrentHr() {
        return ((Hr) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }
}