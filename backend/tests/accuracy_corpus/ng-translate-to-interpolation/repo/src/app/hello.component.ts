import { Component } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

@Component({ selector: 'app-hello', template: '<p>{{ msg }}</p>' })
export class HelloComponent {
  constructor(private translate: TranslateService) {}
  msg = '';

  show() {
    this.msg = this.translate.instant('GREETING');
  }
}
