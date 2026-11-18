package pro.hirdman.radar.burp;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Proxy fakes of Montoya interfaces: answers by method name, empty Optional/List otherwise. */
public final class Fakes {

    /** Returned by an {@link Answer} to fall back to the defaults. */
    public static final Object DEFAULT = new Object();

    @FunctionalInterface
    public interface Answer {
        Object answer(String method, Object[] args) throws Throwable;
    }

    private Fakes() {
    }

    public static <T> T fake(Class<T> type, Map<String, Object> answers) {
        return fake(type, (name, args) -> answers.containsKey(name) ? answers.get(name) : DEFAULT);
    }

    @SuppressWarnings("unchecked")
    public static <T> T fake(Class<T> type, Answer answer) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (p, m, args) -> {
            Object a = answer.answer(m.getName(), args == null ? new Object[0] : args);
            if (a != DEFAULT) {
                return a;
            }
            if (m.getReturnType() == Optional.class) {
                return Optional.empty();
            }
            if (m.getReturnType() == List.class) {
                return List.of();
            }
            if (m.getReturnType() == void.class) {
                return null;
            }
            throw new UnsupportedOperationException(type.getSimpleName() + "." + m.getName());
        });
    }
}
