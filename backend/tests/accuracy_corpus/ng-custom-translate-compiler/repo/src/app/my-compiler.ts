import { TranslateCompiler } from '@ngx-translate/core';

export class MyCompiler implements TranslateCompiler {
  compile(value: string) { return value; }
  compileTranslations(t: any) { return t; }
}
