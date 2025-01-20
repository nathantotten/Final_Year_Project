// Credit to: https://github.com/dmadunic/clidemo under GPL 3.0 Licence

package org.ntotten.csproject.backend.shell;

import org.jline.utils.AttributedString;
import org.jline.utils.AttributedStyle;
import org.springframework.shell.jline.PromptProvider;
import org.springframework.stereotype.Component;

@Component
public class CustomPromptProvider implements PromptProvider {
    @Override
    public AttributedString getPrompt() {
        return new AttributedString("NT-SSE-APP:> ", AttributedStyle.DEFAULT.foreground(AttributedStyle.BLUE));
    }
}
