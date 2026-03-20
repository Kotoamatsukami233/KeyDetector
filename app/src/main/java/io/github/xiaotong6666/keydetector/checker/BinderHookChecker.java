package io.github.xiaotong6666.keydetector.checker;

import io.github.xiaotong6666.keydetector.CheckerContext;
import io.github.xiaotong6666.keydetector.handler.BinderHookHandler;

public final class BinderHookChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        return !BinderHookHandler.isHookSuccess();
    }

    @Override
    public String description() {
        return "Hook Failed (%d)\n尝试 Hook ServiceManager 失败";
    }
}
