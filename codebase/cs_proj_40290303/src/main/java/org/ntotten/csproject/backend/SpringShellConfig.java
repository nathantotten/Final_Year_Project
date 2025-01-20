// Credit to: https://github.com/dmadunic/clidemo under GPL 3.0 Licence

package org.ntotten.csproject.backend;

import org.jline.reader.LineReader;
import org.jline.terminal.Terminal;
import org.ntotten.csproject.backend.shell.InputReader;
import org.ntotten.csproject.backend.shell.ShellHelper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

@Configuration
public class SpringShellConfig {

    @Bean
    public ShellHelper shellHelper(@Lazy Terminal terminal) {
        return new ShellHelper(terminal);
    }

    @Bean
    public InputReader inputReader(@Lazy LineReader lineReader) {
        return new InputReader(lineReader);
    }

}
