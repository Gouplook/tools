package main__test

import (
	"fmt"
	"testing"
	"tools/rsa2"
)

func TestRsa2(t *testing.T) {
	rsa2Ver := new(rsa2.Rsa2Verify)
	rsa2Ver.PubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqq4UomXPukiHYcZCCBFtCgO5KPlppLeRwnglbSZSnxskKaLv26TK400ZULXQLfF08ApZXalpndPZD0+lepOloM25w+JGypXT8WqpOWNpZZ+qObOkpDC0Kf4YBt+HYd7hSxgHoaCgJovGyA3+I8SimQ3lLldh7NFn9LTp2agLvLCFhYH19IJZO+MX4GoHQQMkHAhjkfS5V5FQ03bXBXHtyJVo6iDuRkak8cE+PzEFdBc7t56QXAYpGiqJH1OG+l/O2aCv9T1DK5mHmmPAKbMa0TmgWnUWTgOhYjSbZJ5AQS5rVvoRI0fcS4JxRzBVeXPsD1wMw7xamny5+KKq2HVA8QIDAQAB"
	rsa2Ver.PrivateKey = "MIIEpQIBAAKCAQEAqq4UomXPukiHYcZCCBFtCgO5KPlppLeRwnglbSZSnxskKaLv26TK400ZULXQLfF08ApZXalpndPZD0+lepOloM25w+JGypXT8WqpOWNpZZ+qObOkpDC0Kf4YBt+HYd7hSxgHoaCgJovGyA3+I8SimQ3lLldh7NFn9LTp2agLvLCFhYH19IJZO+MX4GoHQQMkHAhjkfS5V5FQ03bXBXHtyJVo6iDuRkak8cE+PzEFdBc7t56QXAYpGiqJH1OG+l/O2aCv9T1DK5mHmmPAKbMa0TmgWnUWTgOhYjSbZJ5AQS5rVvoRI0fcS4JxRzBVeXPsD1wMw7xamny5+KKq2HVA8QIDAQABAoIBAFOZWHoCrDBt/gGh/g29m07ga/zpzRjk4PwDpTFFKArOXHQYXquSl92lkdS6ePFH5yL7rrH1nMm1Tgf11vOnBeUxXt/XIR1xLZJ9z81QJ/uirNn+Z5IUWOqIjnQvYDxL0sXZS0ObTVYT+JVcZTJXydx1td9w5YH9P5HYWwJFERql/gHGCd74+4NR3K5vn2grSROjLHWq8ZLBSiiWg2WXw0LwkgZ1XscBhW6oVJ8c16kXsYiKi+827VIOovPYSm0d0Zz0BirjgGvoxCxQ1gtlHddNj6ti5Mdnw1d6F+lX4caqvHPhIrVu7CXufCcuX+PkYUn0wemUwY1z5OWQjlbyocECgYEA416BStg14dbbyu9vES3r82r5WU29Loqhrpp8nwGtFP4/WT7xA84jYD++YlKT2ULmGBTR+fhaSSf5ieuVd2dqNDpHq1M5AMR7q39xxVNEm4Sjn60+cXHXnP9rkJJMeBQpfqNmscYxMyLgx1A/Rg0WLdKf/zYFIp1mzWm69d+2ncUCgYEAwCwjYPdV22598BO/zaiV++e74A4/E6Oqh8Mh3vroSAFVal54xC+YFXMW9kdDUbkwKUfJdRpv9jRih68LDNHE5wBoRgFadaOvlGqn88kq9FaLKivegIoGOapbsWCpCUvEXYs9sxTaa52/mgh3drLMx1eUDQ5xrtThNLyro6+GlT0CgYEAitQZfemmfM8ERVUNLCAuAeM/fRfKe7CKKGKL1UrgtADKDWQxJXGoiAxj4wUo4W/HrsyHqWnLNwABjgUarl2mq10qhaG7HIzcNksK3MGLEqpafhT6G6q3TFVpCE1MA8XL0FdVTRcG04JoXUrSV6OF91Sz/NCvMgOJ0cLNNXPzvUECgYEAoRHdrV5hdgQMRncnIicVXwgCLm+CauGZAyWIdC51FjUX9ImuSzFhFUlbi5x7Tjobpd3neuFnykJp+zO53UrM8JkkzNhBi6xgc9NZZjnMaPNIvVX7rl0Bjr+9DtTnmUUKFyWn1zu5Ps3/VAmYp8KBZOuAydi7bEA9akhgzFdIRDkCgYEAjxmcLopXd7uDmN1EWEOkknZTYii6vS2xQekrKs53jjFLPhkULE1Td7Sxe29vt7aIbH3u/K+5Q+Tkq26YzO3vJYhr2y2EAle6am75xeBp4FsKW5Shl27zlOqw6878uD+CHVT/JbXuqcDALlvGLQSp7rhuR+RQP3RD3mi0vmXOLzI="

	dataStr := "{\"data_key\":\"JC2021111601\",\"data_value\":{\"name\":\"?????????\",\"price\":100.00}}"
	sign, err := rsa2Ver.CreateSign(dataStr)
	fmt.Println("???????????????", err)
	fmt.Println("?????????", sign)
	err = rsa2Ver.VerifySign(dataStr, sign)
	if err != nil {
		fmt.Println("???????????????", err)
	} else {
		fmt.Println("????????????")
	}

}
