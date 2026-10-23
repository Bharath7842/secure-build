import { Component } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

@Component({ selector: 'app-rich', templateUrl: './rich.component.html' })
export class RichComponent {
  constructor(private translate: TranslateService, private sanitizer: any) {}
  html = '';
  safeHtml: any;

  show(key: string) {
    this.html = this.translate.instant(key);
    this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(this.html);
  }
}
