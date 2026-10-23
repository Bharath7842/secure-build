import { Component } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

@Component({ selector: 'app-err', templateUrl: './err.component.html' })
export class ErrComponent {
  constructor(private translate: TranslateService) {}
  errorMsg: string[] = [];

  load(key: string) {
    this.translate.get(key).subscribe((res: string) => {
      this.errorMsg.push(res);
    });
  }
}
