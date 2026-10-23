import { Component } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

@Component({ selector: 'app-custom', template: '<p>{{ msg }}</p>' })
export class CustomComponent {
  constructor(private translate: TranslateService) {}
  msg = '';

  show() {
    this.msg = this.translate.instant('K');
  }
}
